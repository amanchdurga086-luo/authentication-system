# Authentication System

A production-oriented REST API authentication system built with Node.js, Express, MongoDB, and JWT. It demonstrates secure authentication, refresh-token rotation, server-side sessions, RBAC, password recovery, email verification, validation, and centralized error handling.

## Features

- User registration and input validation
- Secure password hashing with bcrypt
- JWT access-token authentication
- HttpOnly cookie-based authentication
- Refresh-token rotation
- SHA-256 hashing of refresh tokens before database storage
- Refresh-token reuse detection
- Server-side session tracking and revocation
- Logout current session
- Logout all devices
- Password change with session revocation
- Forgot-password and password-reset flows
- Expiring, single-use password reset tokens
- Email verification with expiring tokens
- Role-based access control (RBAC)
- Centralized async error handling
- Custom API error/response utilities
- MongoDB transactions for security-sensitive token operations
- Environment-based configuration
- Postman security and functional testing

## Tech Stack

Node.js, Express.js, MongoDB, Mongoose, JWT, bcrypt, express-validator, cookie-parser, dotenv, Nodemailer.

## Project Structure

```text
authentication-system/
├── config/
│   └── db.js
├── controllers/
│   └── auth.controller.js
├── middleware/
│   ├── auth.middleware.js
│   ├── authorize.middleware.js
│   ├── error.middleware.js
│   └── validate.middleware.js
├── models/
│   ├── User.js
│   ├── Session.js
│   └── RefreshToken.js
├── routes/
│   └── auth.routes.js
├── utils/
│   ├── ApiError.js
│   ├── ApiResponse.js
│   ├── asyncHandler.js
│   ├── sendEmail.js
│   └── sendToken.js
├── validators/
│   └── auth.validator.js
├── app.js
├── server.js
└── package.json
```

## Authentication Architecture

### Access Token

After successful login, the server creates a short-lived JWT containing the user's identity and role and sends it as an HttpOnly cookie.

### Refresh Token

Refresh tokens are cryptographically random opaque values. The raw token is never stored in MongoDB; only its SHA-256 hash is stored.

```text
Raw Refresh Token → SHA-256 → Database Hash
```

### Refresh Token Rotation

Each successful refresh consumes the previous refresh token and creates a new one.

```text
Refresh Token A
      ↓
   /refresh
      ↓
A → usedAt set
      ↓
Refresh Token B created
```

If an already-used refresh token is presented again, the associated session is revoked.

## Session Management

Each login creates a server-side session associated with the user and a token family. Refresh-token records reference that session.

This allows the application to:

- Revoke the current session
- Revoke all sessions for a user
- Detect refresh-token reuse
- Prevent revoked sessions from refreshing access tokens

## Authorization

Authentication and authorization are separate concerns:

```text
authenticate
    ↓
Identify user
    ↓
authorize("admin")
    ↓
Check role
```

A normal authenticated user receives `403 Forbidden` when accessing an admin-only resource, while an unauthenticated request receives `401 Unauthorized`.

## Password Security

Passwords are hashed with bcrypt before storage. Plaintext passwords are never stored.

Password changes and password resets revoke existing sessions so previously issued refresh tokens cannot be used to regain access.

### Password Reset

![
Forgot Password->
Generate random reset token->
Hash token->
Store hash + expiry->
Send reset link->
Reset password->
Invalidate reset token->
Revoke existing sessions
](./assets/reset_password.png)



## Email Verification

Users can request a verification link. The verification token is stored as a hash with an expiration time. Successful verification sets `isVerified` to `true` and removes the token.

## API Endpoints

Base URL: `http://localhost:5000/api/v1/auth`

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | `/register` | Public | Register a user |
| POST | `/login` | Public | Authenticate and create session |
| GET | `/profile` | Required | Get current user |
| GET | `/admin` | Admin | Access admin resource |
| POST | `/logout` | Public | Logout current session |
| POST | `/refresh-token` | Public | Rotate refresh token |
| POST | `/logout-all` | Required | Revoke all user sessions |
| PUT | `/change-password` | Required | Change password and revoke sessions |
| POST | `/forgot-password` | Public | Request password reset |
| PUT | `/reset-password/:token` | Public | Reset password |
| POST | `/send-verification-email` | Required | Send verification email |
| GET | `/verify-email/:token` | Public | Verify email |

## Environment Variables

Create `.env`:

```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://127.0.0.1:27017/authentication-system?replicaSet=rs0
JWT_SECRET=your_strong_jwt_secret
ACCESS_TOKEN_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_IN=7d
EMAIL_HOST=your_smtp_host
EMAIL_PORT=587
EMAIL_USER=your_email
EMAIL_PASS=your_email_password
```


## Installation

```bash
npm install
npm run dev
```

The API runs at `http://localhost:5000`.

## MongoDB Transactions

Security-sensitive refresh-token operations use MongoDB transactions. Local MongoDB must run as a replica set.

Example:

```text
mongodb://127.0.0.1:27017/authentication-system?replicaSet=rs0
```

## Error Handling

Rejected async controller promises are forwarded through `asyncHandler` to centralized error middleware.

```text
Controller
   ↓
asyncHandler
   ↓
Error
   ↓
Global error middleware
   ↓
Consistent JSON response
```

## Testing

The system was manually tested with Postman.

Verified flows include:

- Server and MongoDB connection
- Registration
- Login
- Authentication middleware
- Role-based authorization
- Refresh-token rotation
- Refresh-token reuse detection
- Logout
- Logout all devices
- Password change
- Forgot-password email delivery
- Password reset
- Email verification
- Request validation

Security checks included invalid credentials, missing/invalid access tokens, unauthorized roles, refresh-token reuse, refresh after session revocation, old password rejection, and reset-token reuse.

## Security Highlights

- bcrypt password hashing
- HttpOnly authentication cookies
- Random opaque refresh tokens
- SHA-256 refresh-token hashes in MongoDB
- Refresh-token rotation and reuse detection
- Server-side session revocation
- Session invalidation after password changes/resets
- Separate authentication and authorization middleware
- MongoDB transactions for token operations
- Request validation
- Environment-based secrets

## Future Improvements

- Rate limiting
- Helmet security headers
- Strict production CORS
- Account-enumeration protection for forgot-password
- Automated unit/integration tests
- Active session listing and per-session revocation
- Swagger/OpenAPI documentation
- Docker and CI/CD
- Production deployment
- Optional 2FA/OAuth