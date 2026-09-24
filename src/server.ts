
import cors from 'cors';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import { applicationDefault, cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { FieldValue, getFirestore, Timestamp } from 'firebase-admin/firestore';
import sgMail from '@sendgrid/mail';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { z } from 'zod';

dotenv.config();

// Basic Express app and environment configuration.
const app = express();
const PORT = Number(process.env.PORT ?? 3000);
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const SENDER_MAIL = process.env.SENDGRID_FROM_EMAIL ?? process.env.SENDER_MAIL;
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY ?? process.env.VITE_FIREBASE_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '1h';

// Initialise Firebase Admin once, using either JSON credentials or ADC.
function initialiseFirebase() {
  if (getApps().length > 0) return getApps()[0];

  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    return initializeApp({ credential: cert(JSON.parse(serviceAccountJson)) });
  }

  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS is required.');
  }

  return initializeApp({ credential: applicationDefault() });
}

// Keep the server available for public health checks if Firebase is unavailable.
let firebaseReady = true;
try {
  initialiseFirebase();
} catch {
  firebaseReady = false;
  console.warn('Firebase Admin is not configured. Protected routes are disabled.');
}

const auth = firebaseReady ? getAuth() : null;
const db = firebaseReady ? getFirestore() : null;

if (SENDGRID_API_KEY && SENDER_MAIL) sgMail.setApiKey(SENDGRID_API_KEY);

type AuthenticatedRequest = Request & { user?: { uid: string; email?: string } };

// Request validation schemas keep bad data out of Firestore.
const registrationSchema = z.object({
  firstName: z.string().trim().min(1).max(50),
  lastName: z.string().trim().min(1).max(50),
  email: z.string().email(),
  password: z.string().min(6).max(128),
  confirmPassword: z.string().min(6).max(128),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match.',
  path: ['confirmPassword'],
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(128),
});

const upgradeSchema = z.object({
  name: z.string().trim().min(2).max(100),
  cardNumber: z.string().regex(/^\d{13,19}$/),
  expiryMonth: z.coerce.number().int().min(1).max(12),
  expiryYear: z.coerce.number().int().min(new Date().getFullYear()),
  cvv: z.string().regex(/^\d{3,4}$/),
});

const postSchema = z.object({
  type: z.enum(['question', 'article']),
  plan: z.enum(['free', 'paid']),
  title: z.string().trim().min(3).max(200),
  description: z.string().trim().max(10000).nullable().optional(),
  abstract: z.string().trim().max(5000).nullable().optional(),
  articleText: z.string().trim().max(100000).nullable().optional(),
  tags: z.array(z.string().trim().min(1).max(50)).max(3),
}).superRefine((post, context) => {
  if (post.type === 'question' && (!post.description || post.description.trim().length === 0)) {
    context.addIssue({ code: 'custom', path: ['description'], message: 'Questions require a description.' });
  }
  if (post.type === 'article' && (!post.abstract || post.abstract.trim().length === 0 || !post.articleText || post.articleText.trim().length === 0)) {
    context.addIssue({ code: 'custom', path: ['articleText'], message: 'Articles require an abstract and article text.' });
  }
});

const postFilterSchema = z.object({
  type: z.enum(['question', 'article']).optional(),
  plan: z.enum(['free', 'paid']).optional(),
  tag: z.string().trim().min(1).max(50).optional(),
});

const commentSchema = z.object({
  content: z.string().trim().min(1).max(5000),
  parentCommentId: z.string().trim().min(1).max(200).nullable().optional(),
});

const postUpdateSchema = z.object({
  type: z.enum(['question', 'article']).optional(),
  plan: z.enum(['free', 'paid']).optional(),
  title: z.string().trim().min(3).max(200).optional(),
  description: z.string().trim().max(10000).nullable().optional(),
  abstract: z.string().trim().max(5000).nullable().optional(),
  articleText: z.string().trim().max(100000).nullable().optional(),
  tags: z.array(z.string().trim().min(1).max(50)).max(3).optional(),
});

app.use(cors({ origin: process.env.FRONTEND_URL ?? true }));
app.use(express.json());

// Reject protected requests when Firebase is not configured.
function requireFirebase(_req: Request, res: Response, next: NextFunction) {
  if (!firebaseReady || !auth || !db) {
    return res.status(503).json({ error: 'Firebase Admin is not configured on the server.' });
  }
  next();
}

// Verify the backend JWT and attach the user ID to the request.
async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined;

  if (!token || !JWT_SECRET) return res.status(401).json({ error: 'A backend session token is required.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    if (typeof decoded.sub !== 'string') throw new Error('JWT subject is missing.');
    req.user = { uid: decoded.sub, email: typeof decoded.email === 'string' ? decoded.email : undefined };
    next();
  } catch {
    return res.status(401).json({ error: 'The backend session token is invalid or expired.' });
  }
}

app.get('/', (_req, res) => res.json({ message: 'DEV@Deakin backend is running.' }));

app.get('/api/health', (_req, res) => {
  res.json({
    firebase: firebaseReady,
    firebaseAuthApi: Boolean(FIREBASE_API_KEY),
    jwt: Boolean(JWT_SECRET),
    email: Boolean(SENDGRID_API_KEY && SENDER_MAIL),
  });
});

// Create or update the Firestore profile used by the rest of the API.
async function saveUserProfile(
  uid: string,
  email: string,
  displayName?: string,
  name?: { firstName: string; lastName: string },
) {
  if (!db) throw new Error('Firestore is not configured.');
  const userRef = db.collection('users').doc(uid);
  const existing = await userRef.get();
  const data = {
    uid,
    email,
    ...(displayName ? { displayName } : {}),
    ...(name ?? {}),
    ...(existing.exists ? {} : { plan: 'free', createdAt: Timestamp.now() }),
    updatedAt: Timestamp.now(),
  };

  await userRef.set(data, { merge: true });
  return { created: !existing.exists, user: { ...data, plan: existing.data()?.plan ?? data.plan } };
}

// Use Firebase Auth REST endpoints for email/password authentication.
async function firebasePasswordRequest(action: 'signUp' | 'signInWithPassword', email: string, password: string) {
  console.log(`[firebase-auth] ${action} started`, { email });
  if (!FIREBASE_API_KEY) {
    console.error('[firebase-auth] FIREBASE_API_KEY is missing.');
    throw new Error('FIREBASE_API_KEY is not configured.');
  }

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:${action}?key=${FIREBASE_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    },
  );
  const result = await response.json() as Record<string, unknown>;
  if (!response.ok) {
    const firebaseCode = String((result.error as { message?: string } | undefined)?.message ?? 'AUTH_ERROR');
    console.error(`[firebase-auth] ${action} failed`, { email, firebaseCode, status: response.status });
    throw new Error(firebaseCode);
  }
  console.log(`[firebase-auth] ${action} succeeded`, { email });
  return result as { localId: string; email: string; idToken: string; refreshToken: string; expiresIn: string };
}

// Create the short-lived token used by protected backend routes.
function createSessionToken(uid: string, email: string) {
  if (!JWT_SECRET) throw new Error('JWT_SECRET is not configured.');
  return jwt.sign({ email }, JWT_SECRET, { subject: uid, expiresIn: JWT_EXPIRES_IN });
}

// Convert Firebase auth error codes into messages suitable for the frontend.
function authErrorMessage(error: unknown) {
  const code = error instanceof Error ? error.message : '';
  const messages: Record<string, string> = {
    EMAIL_EXISTS: 'An account with this email already exists.',
    INVALID_LOGIN_CREDENTIALS: 'The email or password is incorrect.',
    EMAIL_NOT_FOUND: 'The email or password is incorrect.',
    INVALID_PASSWORD: 'The email or password is incorrect.',
    INVALID_EMAIL: 'Enter a valid email address.',
    WEAK_PASSWORD: 'Password must be at least 6 characters.',
  };
  return messages[code] ?? 'Authentication request failed.';
}

// Authentication routes.
app.post(['/api/auth/register', '/api/users/register'], requireFirebase, async (req, res) => {
  console.log('[register] request received', {
    email: req.body?.email ?? '[missing]',
    hasFirstName: Boolean(req.body?.firstName),
    hasLastName: Boolean(req.body?.lastName),
    hasPassword: Boolean(req.body?.password),
    hasConfirmPassword: Boolean(req.body?.confirmpassword),
  });
  const parsed = registrationSchema.safeParse(req.body);
  if (!parsed.success || !db) {
    console.warn('[register] validation/Firebase check failed', {
      firebaseReady: Boolean(db),
      issues: parsed.success ? [] : parsed.error.issues.map((issue) => issue.path.join('.')),
    });
    return res.status(400).json({ error: parsed.success ? 'Firebase server is not configured.' : 'Registration details are invalid.' });
  }

  try {
    const result = await firebasePasswordRequest('signUp', parsed.data.email, parsed.data.password);
    const displayName = `${parsed.data.firstName} ${parsed.data.lastName}`;
    const profile = await saveUserProfile(result.localId, result.email, displayName, {
      firstName: parsed.data.firstName,
      lastName: parsed.data.lastName,
    });
    const sessionToken = createSessionToken(result.localId, result.email);
    console.log('[register] completed', { email: result.email, profileCreated: profile.created });
    return res.status(201).json({
      sessionToken,
      token: sessionToken,
      accessToken: sessionToken,
      user: { ...profile.user, firstName: parsed.data.firstName, lastName: parsed.data.lastName },
    });
  } catch (error) {
    console.error('[register] failed', { message: error instanceof Error ? error.message : 'Unknown error' });
    return res.status(400).json({ error: authErrorMessage(error) });
  }
});

app.post(['/api/auth/login', '/api/users/login'], requireFirebase, async (req, res) => {
  console.log('[login] request received', {
    email: req.body?.email ?? '[missing]',
    hasPassword: Boolean(req.body?.password),
  });
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    console.warn('[login] validation failed', {
      issues: parsed.error.issues.map((issue) => issue.path.join('.')),
    });
    return res.status(400).json({ error: 'A valid email and password are required.' });
  }

  try {
    const result = await firebasePasswordRequest('signInWithPassword', parsed.data.email, parsed.data.password);
    const profile = await saveUserProfile(result.localId, result.email);
    const sessionToken = createSessionToken(result.localId, result.email);
    console.log('[login] completed', {
      email: result.email,
      plan: profile.user.plan,
      tokenFieldsPresent: Boolean(sessionToken),
    });
    return res.json({
      sessionToken,
      token: sessionToken,
      accessToken: sessionToken,
      user: profile.user,
    });
  } catch (error) {
    console.error('[login] failed', { message: error instanceof Error ? error.message : 'Unknown error' });
    return res.status(401).json({ error: authErrorMessage(error) });
  }
});

app.post('/api/users/sync', requireFirebase, requireAuth, async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({
    email: z.string().email(),
    displayName: z.string().trim().min(1).max(80).optional(),
  }).safeParse(req.body);
  if (!parsed.success || !req.user || !db) {
    return res.status(400).json({ error: 'A valid email and optional display name are required.' });
  }

  const profile = await saveUserProfile(req.user.uid, req.user.email ?? parsed.data.email, parsed.data.displayName);
  return res.status(profile.created ? 201 : 200).json({ user: profile.user });
});

app.get('/api/users/me', requireFirebase, requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!req.user || !db) return res.status(401).json({ error: 'Unauthenticated request.' });
  const snapshot = await db.collection('users').doc(req.user.uid).get();
  const profile = snapshot.exists
    ? snapshot.data()
    : { uid: req.user.uid, email: req.user.email, plan: 'free' };
  return res.json({ user: profile });
});

// Create posts and save their ownership metadata.
app.post('/api/posts', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  const parsed = postSchema.safeParse(req.body);
  if (!parsed.success || !req.user || !db) {
    return res.status(400).json({
      error: 'Invalid post data.',
      ...(parsed.success ? {} : { details: parsed.error.flatten() }),
    });
  }

  try {
    const userSnapshot = await db.collection('users').doc(req.user.uid).get();
    const user = userSnapshot.data();
    const accountPlan = String(user?.plan ?? 'free').toLowerCase();
    if (parsed.data.plan === 'paid' && accountPlan !== 'paid') {
      return res.status(403).json({ error: 'A paid account is required to create paid posts.' });
    }

    const profileName = [user?.firstName, user?.lastName].filter(Boolean).join(' ');
    const author = user?.displayName ?? user?.name ?? (profileName || req.user.email || req.user.uid);
    const post = {
      type: parsed.data.type,
      plan: parsed.data.plan,
      title: parsed.data.title,
      description: parsed.data.type === 'question' ? parsed.data.description : null,
      abstract: parsed.data.type === 'article' ? parsed.data.abstract : null,
      articleText: parsed.data.type === 'article' ? parsed.data.articleText : null,
      tags: parsed.data.tags,
      userId: req.user.uid,
      createdBy: req.user.uid,
      author,
      createdAt: FieldValue.serverTimestamp(),
    };
    const postReference = await db.collection('posts').add(post);
    return res.status(201).json({
      post: {
        id: postReference.id,
        type: post.type,
        plan: post.plan,
        title: post.title,
        description: post.description,
        abstract: post.abstract,
        articleText: post.articleText,
        tags: post.tags,
        userId: post.userId,
        createdBy: post.createdBy,
        author: post.author,
        comments: [],
      },
    });
  } catch (error) {
    console.error('[posts] create failed', error);
    return res.status(500).json({ error: 'Unable to save the post.' });
  }
});

// Return posts owned by the current user, including their comments.
app.get('/api/users/me/posts', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  if (!req.user || !db) return res.status(401).json({ error: 'Unauthenticated request.' });

  try {
    const [userIdSnapshot, createdBySnapshot] = await Promise.all([
      db.collection('posts').where('userId', '==', req.user.uid).get(),
      db.collection('posts').where('createdBy', '==', req.user.uid).get(),
    ]);
    const documents = new Map(userIdSnapshot.docs.map((document) => [document.id, document]));
    createdBySnapshot.docs.forEach((document) => documents.set(document.id, document));
    const posts = await Promise.all(Array.from(documents.values()).map(async (document) => {
      const data = document.data();
      const commentsSnapshot = await document.ref.collection('comments').get();
      const comments = commentsSnapshot.docs.map((commentDocument) => {
        const comment = commentDocument.data();
        return {
          id: commentDocument.id,
          postId: document.id,
          userId: typeof comment.userId === 'string' ? comment.userId : null,
          parentCommentId: typeof comment.parentCommentId === 'string' ? comment.parentCommentId : null,
          content: typeof comment.content === 'string' ? comment.content : '',
          author: typeof comment.author === 'string' ? comment.author : null,
          createdAt: comment.createdAt instanceof Timestamp ? comment.createdAt.toDate().toISOString() : null,
        };
      });
      const createdAt = data.createdAt instanceof Timestamp ? data.createdAt.toDate().toISOString() : null;
      return {
        id: document.id,
        type: data.type ?? null,
        plan: data.plan ?? null,
        title: data.title ?? null,
        description: data.description ?? null,
        abstract: data.abstract ?? null,
        articleText: data.articleText ?? null,
        tags: Array.isArray(data.tags) ? data.tags : [],
        author: data.author ?? null,
        createdBy: data.createdBy ?? data.userId ?? null,
        createdAt,
        comments,
      };
    }));
    posts.sort((left, right) => Date.parse(right.createdAt ?? '') - Date.parse(left.createdAt ?? ''));
    return res.json({ posts });
  } catch (error) {
    console.error('[posts] own list failed', error);
    return res.status(500).json({ error: 'Unable to load your posts.' });
  }
});

// Update an owned post without replacing its comments subcollection.
app.patch('/api/posts/:postId', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  const parsed = postUpdateSchema.safeParse(req.body);
  const postId = typeof req.params.postId === 'string' ? req.params.postId : undefined;
  if (!parsed.success || !postId || !req.user || !db) {
    return res.status(400).json({
      error: 'Invalid post data.',
      ...(parsed.success ? {} : { details: parsed.error.flatten() }),
    });
  }

  try {
    const postReference = db.collection('posts').doc(postId);
    const postSnapshot = await postReference.get();
    if (!postSnapshot.exists) return res.status(404).json({ error: 'Post not found.' });

    const existing = postSnapshot.data() ?? {};
    const ownerId = existing.userId ?? existing.createdBy;
    if (ownerId !== req.user.uid) return res.status(403).json({ error: 'You do not own this post.' });

    if (parsed.data.plan === 'paid') {
      const userSnapshot = await db.collection('users').doc(req.user.uid).get();
      if (String(userSnapshot.data()?.plan ?? 'free').toLowerCase() !== 'paid') {
        return res.status(403).json({ error: 'A paid account is required for paid posts.' });
      }
    }

    const updates = Object.fromEntries(Object.entries(parsed.data).filter(([, value]) => value !== undefined));
    if (updates.type === 'question') {
      updates.abstract = null;
      updates.articleText = null;
    } else if (updates.type === 'article') {
      updates.description = null;
    }
    await postReference.update(updates);
    const updated = { ...existing, ...updates };
    const commentsSnapshot = await postReference.collection('comments').get();
    const comments = commentsSnapshot.docs.map((commentDocument) => {
      const comment = commentDocument.data();
      return {
        id: commentDocument.id,
        postId,
        userId: typeof comment.userId === 'string' ? comment.userId : null,
        parentCommentId: typeof comment.parentCommentId === 'string' ? comment.parentCommentId : null,
        content: typeof comment.content === 'string' ? comment.content : '',
        author: typeof comment.author === 'string' ? comment.author : null,
        createdAt: comment.createdAt instanceof Timestamp ? comment.createdAt.toDate().toISOString() : null,
      };
    });
    return res.json({
      post: {
        id: postId,
        title: updated.title ?? null,
        type: updated.type ?? null,
        plan: updated.plan ?? null,
        description: updated.description ?? null,
        abstract: updated.abstract ?? null,
        articleText: updated.articleText ?? null,
        tags: updated.tags ?? [],
        author: updated.author ?? null,
        createdBy: updated.createdBy ?? updated.userId ?? null,
        comments,
      },
    });
  } catch (error) {
    console.error('[posts] update failed', error);
    return res.status(500).json({ error: 'Unable to update the post.' });
  }
});

// Notification routes are scoped to the authenticated recipient.
app.get('/api/notifications', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  if (!req.user || !db) return res.status(401).json({ error: 'Unauthenticated request.' });

  try {
    const snapshot = await db.collection('notifications').where('recipientId', '==', req.user.uid).get();
    const notifications = snapshot.docs.map((document) => {
      const data = document.data();
      return {
        id: document.id,
        type: data.type ?? null,
        message: data.message ?? null,
        postId: data.postId ?? null,
        commentId: data.commentId ?? null,
        read: data.read === true,
        createdAt: data.createdAt instanceof Timestamp ? data.createdAt.toDate().toISOString() : null,
      };
    });
    notifications.sort((left, right) => Date.parse(right.createdAt ?? '') - Date.parse(left.createdAt ?? ''));
    return res.json({ notifications });
  } catch (error) {
    console.error('[notifications] list failed', error);
    return res.status(500).json({ error: 'Unable to load notifications.' });
  }
});

app.patch('/api/notifications/:notificationId/read', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  const notificationId = typeof req.params.notificationId === 'string' ? req.params.notificationId : undefined;
  if (!notificationId || !req.user || !db) return res.status(400).json({ error: 'A valid notification ID is required.' });

  try {
    const notificationReference = db.collection('notifications').doc(notificationId);
    const snapshot = await notificationReference.get();
    if (!snapshot.exists || snapshot.data()?.recipientId !== req.user.uid) {
      return res.status(404).json({ error: 'Notification not found.' });
    }
    await notificationReference.update({ read: true });
    return res.json({ notification: { id: notificationId, read: true } });
  } catch (error) {
    console.error('[notifications] mark read failed', error);
    return res.status(500).json({ error: 'Unable to mark notification as read.' });
  }
});

app.patch('/api/notifications/read-all', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  if (!req.user || !db) return res.status(401).json({ error: 'Unauthenticated request.' });

  try {
    const snapshot = await db.collection('notifications').where('recipientId', '==', req.user.uid).get();
    if (snapshot.empty) return res.json({ updated: 0 });
    const batch = db.batch();
    snapshot.docs.forEach((document) => batch.update(document.ref, { read: true }));
    await batch.commit();
    return res.json({ updated: snapshot.size });
  } catch (error) {
    console.error('[notifications] mark all read failed', error);
    return res.status(500).json({ error: 'Unable to mark notifications as read.' });
  }
});

app.delete('/api/posts/:postId', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res: Response) => {
  const postId = typeof req.params.postId === 'string' ? req.params.postId : undefined;
  if (!postId || !req.user || !db) return res.status(400).json({ error: 'A valid post ID is required.' });

  try {
    const postReference = db.collection('posts').doc(postId);
    const postSnapshot = await postReference.get();
    if (!postSnapshot.exists) return res.status(404).json({ error: 'Post not found.' });
    const existing = postSnapshot.data() ?? {};
    if ((existing.userId ?? existing.createdBy) !== req.user.uid) {
      return res.status(403).json({ error: 'You do not own this post.' });
    }

    await postReference.delete();
    return res.json({ message: 'Post deleted successfully.' });
  } catch (error) {
    console.error('[posts] delete failed', error);
    return res.status(500).json({ error: 'Unable to delete the post.' });
  }
});

// Add a comment or reply and create the matching notification.
app.post('/api/posts/:postId/comments', requireAuth, requireFirebase, async (req: AuthenticatedRequest, res) => {
  const parsed = commentSchema.safeParse(req.body);
  const postId = typeof req.params.postId === 'string' ? req.params.postId : undefined;
  if (!parsed.success || !postId || !req.user || !db) {
    return res.status(400).json({
      error: 'Invalid comment data.',
      ...(parsed.success ? {} : { details: parsed.error.flatten() }),
    });
  }

  try {
    const postReference = db.collection('posts').doc(postId);
    const postSnapshot = await postReference.get();
    if (!postSnapshot.exists) return res.status(404).json({ error: 'Post not found.' });

    const parentCommentId = parsed.data.parentCommentId ?? null;
    let parentCommentUserId: string | undefined;
    if (parentCommentId) {
      const parentSnapshot = await postReference.collection('comments').doc(parentCommentId).get();
      if (!parentSnapshot.exists) return res.status(404).json({ error: 'Parent comment not found.' });
      const parentUserId = parentSnapshot.data()?.userId;
      parentCommentUserId = typeof parentUserId === 'string' ? parentUserId : undefined;
    }

    const userSnapshot = await db.collection('users').doc(req.user.uid).get();
    const user = userSnapshot.data();
    const profileName = [user?.firstName, user?.lastName].filter(Boolean).join(' ');
    const author = user?.displayName ?? user?.name ?? (profileName || user?.email || req.user.email || req.user.uid);
    const createdAt = Timestamp.now();
    const comment = {
      content: parsed.data.content,
      author,
      userId: req.user.uid,
      parentCommentId,
      createdAt,
    };
    const commentReference = await postReference.collection('comments').add(comment);

    const postOwnerId = postSnapshot.data()?.userId ?? postSnapshot.data()?.createdBy;
    const recipientId = parentCommentUserId ?? (typeof postOwnerId === 'string' ? postOwnerId : undefined);
    if (recipientId && recipientId !== req.user.uid) {
      const notificationType = parentCommentId ? 'comment_reply' : 'comment';
      await db.collection('notifications').add({
        recipientId,
        type: notificationType,
        message: parentCommentId ? 'Someone replied to your comment.' : 'Someone commented on your post.',
        postId,
        commentId: commentReference.id,
        read: false,
        createdAt,
      });
    }

    return res.status(201).json({
      comment: {
        id: commentReference.id,
        postId,
        userId: req.user.uid,
        parentCommentId,
        content: comment.content,
        author: comment.author,
        createdAt: createdAt.toDate().toISOString(),
      },
    });
  } catch (error) {
    console.error('[comments] create failed', error);
    return res.status(500).json({ error: 'Unable to save the comment.' });
  }
});

// Public post feed; paid posts require a paid authenticated account.
app.get('/api/posts', requireFirebase, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore is not configured.' });

  try {
    let accountPlan = 'free';
    const header = req.header('authorization');
    const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined;
    if (token) {
      if (!JWT_SECRET) return res.status(401).json({ error: 'The backend session token is invalid or expired.' });
      const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
      if (typeof decoded.sub !== 'string') return res.status(401).json({ error: 'The backend session token is invalid or expired.' });
      const userSnapshot = await db.collection('users').doc(decoded.sub).get();
      accountPlan = String(userSnapshot.data()?.plan ?? 'free').toLowerCase();
    }

    const filters = postFilterSchema.safeParse(req.query);
    if (!filters.success) return res.status(400).json({ error: 'Invalid post filters.' });

    let query = db.collection('posts').where('plan', '==', 'free');
    if (accountPlan === 'paid') query = db.collection('posts');
    if (filters.data.type) query = query.where('type', '==', filters.data.type);
    if (filters.data.plan) {
      if (accountPlan !== 'paid' && filters.data.plan === 'paid') return res.json({ posts: [] });
      query = query.where('plan', '==', filters.data.plan);
    }

    const snapshot = await query.get();
    const requestedTag = filters.data.tag?.toLowerCase();
    const posts = await Promise.all(snapshot.docs
      .map(async (document) => {
        const data = document.data();
        const tags = Array.isArray(data.tags) ? data.tags.filter((tag): tag is string => typeof tag === 'string') : [];
        const createdAt = data.createdAt instanceof Timestamp ? data.createdAt.toDate().toISOString() : null;
        const authorId = data.createdBy ?? data.userId;
        const authorSnapshot = authorId
          ? await db.collection('users').doc(String(authorId)).get()
          : null;
        const user = authorSnapshot?.data();
        const profileName = [user?.firstName, user?.lastName].filter(Boolean).join(' ');
        const author = data.author ?? user?.displayName ?? user?.name ?? (profileName || user?.email || authorId || null);
        const commentsSnapshot = await document.ref.collection('comments').get();
        const comments = commentsSnapshot.docs.map((commentDocument) => {
          const comment = commentDocument.data();
          return {
            id: commentDocument.id,
            postId: document.id,
            userId: typeof comment.userId === 'string' ? comment.userId : null,
            parentCommentId: typeof comment.parentCommentId === 'string' ? comment.parentCommentId : null,
            content: typeof comment.content === 'string' ? comment.content : '',
            author: typeof comment.author === 'string' ? comment.author : null,
            createdAt: comment.createdAt instanceof Timestamp ? comment.createdAt.toDate().toISOString() : null,
          };
        });
        comments.sort((left, right) => {
          const leftCreatedAt = left.createdAt ? Date.parse(left.createdAt) : 0;
          const rightCreatedAt = right.createdAt ? Date.parse(right.createdAt) : 0;
          return leftCreatedAt - rightCreatedAt;
        });
        return {
          id: document.id,
          type: data.type ?? null,
          plan: data.plan ?? null,
          title: data.title ?? null,
          description: data.description ?? null,
          abstract: data.abstract ?? null,
          articleText: data.articleText ?? null,
          tags,
          createdAt,
          author,
          createdBy: authorId ?? null,
          comments,
        };
      })
    ).then((postList) => postList.filter((post) => !requestedTag || post.tags.some((tag) => tag.toLowerCase() === requestedTag)));
    posts.sort((left, right) => {
        const leftCreatedAt = left.createdAt ? Date.parse(left.createdAt) : 0;
        const rightCreatedAt = right.createdAt ? Date.parse(right.createdAt) : 0;
        return rightCreatedAt - leftCreatedAt;
      });
    return res.json({ posts });
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ error: 'The backend session token is invalid or expired.' });
    }
    console.error('[posts] list failed', error);
    return res.status(500).json({ error: 'Unable to load posts.' });
  }
});

// Record a validated upgrade and the last four card digits.
app.post('/api/users/upgrade', requireFirebase, requireAuth, async (req: AuthenticatedRequest, res) => {
  const parsed = upgradeSchema.safeParse(req.body);
  if (!parsed.success || !req.user || !db) return res.status(400).json({ error: 'Invalid payment details.' });

  const userRef = db.collection('users').doc(req.user.uid);
  const snapshot = await userRef.get();
  if (snapshot.data()?.plan === 'paid') {
    return res.status(409).json({ error: 'This account is already on the paid plan.' });
  }

  await userRef.set({
    plan: 'paid',
    updatedAt: Timestamp.now(),
    payment: { cardholderName: parsed.data.name, last4: parsed.data.cardNumber.slice(-4) },
  }, { merge: true });

  return res.json({ message: 'Plan upgraded successfully.', plan: 'paid' });
});

// Send the newsletter welcome email through SendGrid.
app.post('/subscribe', async (req, res) => {
  const parsedBody = z.object({
    email: z.string().email().optional(),
    emailAddress: z.string().email().optional(),
  }).safeParse(req.body ?? {});

  const email = parsedBody.success ? (parsedBody.data.email ?? parsedBody.data.emailAddress) : undefined;
  if (!email) return res.status(400).json({ error: 'A valid email is required.' });

  if (!SENDGRID_API_KEY || !SENDER_MAIL) {
    return res.status(503).json({ error: 'Email service is unavailable. Configure SENDGRID_API_KEY and SENDER_MAIL.' });
  }

  try {
    await sgMail.send({
      to: email,
      from: SENDER_MAIL,
      subject: 'Thanks for subscribing to our newsletter!',
      text: 'Welcome to our newsletter. We will email you updates soon.',
      html: '<p>Welcome to our newsletter. We will email you updates soon.</p>',
    });
    return res.status(202).json({ message: 'Subscription received. Welcome email sent.' });
  } catch (error) {
    console.error('SendGrid error:', error);
    return res.status(500).json({ error: 'Unable to send welcome email.' });
  }
});

// Start the HTTP server after all routes have been registered.
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
