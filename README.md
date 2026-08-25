# Ganium API Documentation

Base URL: `http://localhost:8008`

## Build

```bash
go build -o bin/ganium .
```

## Swagger Generation

If you add or change Swagger annotations, regenerate the docs with:

```bash
swag init -g main.go -o docs
```

## Swagger UI

Open:

`/swagger/index.html`

## Authentication

Most protected routes use a JWT in the `Authorization` header:

`Authorization: Bearer <token>`

### Important runtime notes

- MongoDB now reads `MONGO_URI` and `MONGO_DATABASE` from the environment
- If you see `connect: connection refused` on startup, MongoDB is not reachable at the configured URI
- Paystack initialize requires a valid JWT because it uses the authenticated email from the token

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

### `POST /api/investigate`

Runs the security-first investigation pipeline and returns evidence plus the final AI assessment.

Request:

```json
{
  "target": "https://example.com",
  "target_type": "url",
  "case_id": "GAN-8F29A1",
  "network": "",
  "source": "manual",
  "investigation_id": ""
}
```

Supported target types:

- `url`
- `website`
- `wallet`
- `message`
- `case`
- `domain`

### `POST /api/scan`

Runs a scan through the shared investigation pipeline and stores the result.

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
- URL scans gather URL, DNS, redirect, and HTTP evidence before final AI analysis
- Message scans focus on persuasion, urgency, and social-engineering cues
- Wallet scans focus on wallet/address patterns and scam likelihood

### `POST /api/paystack/initialize`

Starts a payment checkout for the authenticated user.

Request:

```json
{
  "plan": "starter",
  "reference": "optional-reference",
  "callback_url": "http://localhost:8008/api/paystack/callback",
  "mode": "hosted"
}
```

Accepted plan fields:

- `plan`
- `plan_code`
- `planCode`
- `planName`

Accepted callback fields:

- `callback_url`
- `callbackUrl`
- `callback`

### `GET /api/paystack/callback`

Handles the Paystack browser redirect and forwards the user back to the app deep link.

Query example:

`/api/paystack/callback?reference=ref_123&status=success`

### `POST /api/paystack/verify`

Verifies a payment reference and credits tokens to the authenticated user.

Request:

```json
{
  "reference": "ref_123"
}
```

### `GET /api/paystack/plans`

Returns the available payment plans.

### `GET /api/paystack/stream`

Streams payment status updates for a reference using Server-Sent Events.

Query example:

`/api/paystack/stream?reference=ref_123`
