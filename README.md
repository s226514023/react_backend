# DEV@Deakin Backend

This is the Express and TypeScript backend for the DEV@Deakin application. It provides authentication, Firestore-backed posts and comments, notifications, paid-plan upgrades, and newsletter subscriptions.

## Stack

- Node.js and Express 5
- TypeScript
- Firebase Admin SDK and Firestore
- Firebase Authentication REST API
- JWT session tokens
- Zod request validation
- SendGrid for newsletter email

## Project structure

```text
src/server.ts       Main Express server, middleware, helpers, and routes
firebase-service-account.json  Local Firebase Admin credentials
dist/               Compiled JavaScript output after building
```

## Requirements

- Node.js with npm
- A Firebase project with Firestore and Email/Password Authentication enabled
- A Firebase Admin service account for local Firestore access

## Configuration

Create a `.env` file in this directory. The important values are:

```env
PORT=3000
JWT_SECRET=replace-with-a-long-random-secret
FIREBASE_API_KEY=your-firebase-web-api-key
GOOGLE_APPLICATION_CREDENTIALS=firebase-service-account.json
FRONTEND_URL=http://localhost:5173
SENDGRID_API_KEY=your-sendgrid-key
SENDER_MAIL=verified-sender@example.com
```

`FIREBASE_API_KEY` can also be provided as `VITE_FIREBASE_API_KEY`. Instead of `GOOGLE_APPLICATION_CREDENTIALS`, the backend accepts Firebase service-account JSON through `FIREBASE_SERVICE_ACCOUNT_JSON`.

Do not commit `.env`, service-account JSON, SendGrid keys, or JWT secrets. The service-account file is read by Firebase Admin and should remain local or be provided through deployment secrets.

## Install and run

```bash
npm install
npm run dev
```

The development server runs at `http://localhost:3000` by default. For a production-style run:

```bash
npm run build
npm start
```

`npm run build` is the main compile check. There is currently no automated test suite configured, so `npm test` remains the package template command and is not a useful verification step yet.

## API overview

### Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/users/sync`
- `GET /api/users/me`

Login and registration return a backend JWT. Send it on protected requests as:

```http
Authorization: Bearer <session-token>
```

### Posts

- `GET /api/posts`
- `POST /api/posts`
- `GET /api/users/me/posts`
- `PATCH /api/posts/:postId`
- `DELETE /api/posts/:postId`

Posts store both `userId` and `createdBy` for ownership compatibility. Post responses include the author and a `comments` array. Only the owner can edit or delete a post, and editing does not replace its comments.

### Comments and notifications

- `POST /api/posts/:postId/comments`
- `GET /api/notifications`
- `PATCH /api/notifications/:notificationId/read`
- `PATCH /api/notifications/read-all`

Comments are stored in the Firestore subcollection `posts/{postId}/comments`. A reply may include `parentCommentId`. Commenting on a post creates a notification for the post owner; replying creates a `comment_reply` notification for the parent commenter.

### Other routes

- `GET /api/health` reports Firebase, JWT, and email configuration status.
- `POST /api/users/upgrade` validates upgrade details and records the paid plan.
- `POST /subscribe` sends a newsletter welcome email through SendGrid.

## Firestore collections

- `users/{uid}` stores account profile and plan information.
- `posts/{postId}` stores post content and ownership metadata.
- `posts/{postId}/comments/{commentId}` stores comments and replies.
- `notifications/{notificationId}` stores recipient-scoped notification records.

The backend uses Firestore timestamps internally and converts them to ISO strings in API responses.

## Notes

- Firebase Admin configuration is optional at process startup so `/` and `/api/health` can still respond when local credentials are missing. Protected routes return `503` until Firebase is configured.
- The post feed currently performs tag/type/plan filtering in Firestore and leaves free-text search to the frontend.
- Notifications are loaded through REST polling. WebSockets are not required for the current frontend flow.
