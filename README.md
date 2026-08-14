# Ganium API Documentation

Base URL: `http://localhost:8008`

## Swagger UI

Open:

`/swagger/index.html`

## Authentication

Most protected routes use a JWT in the `Authorization` header:

`Authorization: Bearer <token>`

## Routes

### `POST /register`

Registers a new user and sends an OTP email.

Request:

```json
{
  "email": "user@example.com",
  "password": "secret123",
  "full_name": "User Name"
}
```

### `POST /login`

Logs a user in and returns a JWT.

Request:

```json
{
  "email": "user@example.com",
  "password": "secret123"
}
```

### `POST /verify-otp`

Verifies the OTP sent to a user email.

Request:

```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

### `POST /resend-otp`

Resends the verification OTP.

Request:

```json
{
  "email": "user@example.com"
}
```

### `POST /forgot-password`

Sends a password reset token.

Request:

```json
{
  "email": "user@example.com"
}
```

### `POST /reset-password`

Resets the user password using the token sent by email.

Request:

```json
{
  "email": "user@example.com",
  "token": "reset-token",
  "newPassword": "new-secret"
}
```

### `POST /api/scan`

Runs a scan through Gemini and stores the result.

Request:

```json
{
  "content": "https://example.com/login",
  "scan_type": "url"
}
```

Supported scan types:

- `basic`
- `mid`
- `advance`
- `message`
- `url`
- `wallet`

Behavior:

- If `scan_type` is missing, the API falls back to `basic`
- URL scans gather URL, DNS, redirect, and HTTP evidence before Gemini analysis
- Message scans focus on persuasion, urgency, and social-engineering cues
- Wallet scans focus on wallet/address patterns and scam likelihood

