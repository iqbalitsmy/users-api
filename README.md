# OAuth2 API — Spring Boot + JWT + OAuth2 Social Login
### Complete Learning Reference (Google + GitHub + Local Auth)

---

## Project Structure

```
oauth2-api/
├── pom.xml
└── src/main/
    ├── java/com/learn/oauth2api/
    │   ├── OAuth2ApiApplication.java               ← STEP 1 : Entry point
    │   │
    │   ├── model/
    │   │   ├── User.java                           ← STEP 2 : Entity (LOCAL + OAuth2)
    │   │   ├── AuthProvider.java                   ← Enum: LOCAL, GOOGLE, GITHUB
    │   │   └── RefreshToken.java                   ← Refresh token stored in DB
    │   │
    │   ├── repository/
    │   │   ├── UserRepository.java                 ← STEP 3a: User DB access
    │   │   └── RefreshTokenRepository.java         ← STEP 3b: Token DB access
    │   │
    │   ├── dto/
    │   │   └── AuthDto.java                        ← STEP 4 : All request/response shapes
    │   │
    │   ├── exception/
    │   │   └── AppExceptions.java                  ← STEP 5 : Custom exceptions
    │   │
    │   ├── security/
    │   │   ├── CustomUserDetailsService.java       ← STEP 11: Load user for JWT filter
    │   │   ├── jwt/
    │   │   │   ├── JwtService.java                 ← STEP 6 : Generate/validate JWT
    │   │   │   └── JwtAuthenticationFilter.java    ← STEP 7 : Intercepts every request
    │   │   └── oauth2/
    │   │       ├── OAuth2UserInfo.java              ← STEP 8a: Abstract provider user info
    │   │       ├── GoogleOAuth2UserInfo.java        ← STEP 8b: Google field mappings
    │   │       ├── GitHubOAuth2UserInfo.java        ← STEP 8c: GitHub field mappings
    │   │       ├── OAuth2UserInfoFactory.java       ← STEP 8d: Factory pattern
    │   │       ├── CustomOAuth2UserService.java     ← STEP 9 : Find/create user after OAuth2
    │   │       ├── OAuth2AuthenticationSuccessHandler.java ← STEP 10a: Issue JWT on success
    │   │       └── OAuth2AuthenticationFailureHandler.java ← STEP 10b: Redirect on failure
    │   │
    │   ├── service/
    │   │   ├── RefreshTokenService.java            ← STEP 12: Create/rotate/delete tokens
    │   │   ├── AuthService.java                    ← STEP 13: Register/login/refresh/logout
    │   │   └── UserService.java                    ← STEP 14: Profile CRUD
    │   │
    │   └── config/
    │       ├── SecurityConfig.java                 ← STEP 15: Wire OAuth2 + JWT together
    │       ├── GlobalExceptionHandler.java         ← STEP 16: Clean JSON error responses
    │       └── DataInitializer.java                ← STEP 19: Seed admin/user on startup
    │
    ├── controller/
    │   ├── AuthController.java                     ← STEP 17: /auth/** endpoints
    │   └── UserController.java                     ← STEP 18: /api/users/** endpoints
    │
    └── resources/
        └── application.properties                 ← JWT, OAuth2, H2, logging config
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  TWO AUTHENTICATION PATHS — both end with the same JWT                       │
│                                                                              │
│  PATH A: Local                        PATH B: Social (OAuth2)               │
│  ─────────────────                    ────────────────────────               │
│  POST /auth/register                  GET /oauth2/authorization/google       │
│  POST /auth/login                         ↓                                  │
│       ↓                               Google Consent Screen                  │
│  DaoAuthenticationProvider            GET /login/oauth2/code/google          │
│  (verify BCrypt password)                 ↓                                  │
│       ↓                               CustomOAuth2UserService                │
│  Issue JWT + Refresh Token            (find or create user in DB)            │
│       ↓                                   ↓                                  │
│  Return TokenResponse JSON            OAuth2SuccessHandler                   │
│                                       (issue JWT + redirect to frontend)     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  From here, IDENTICAL for both paths                                   │  │
│  │                                                                        │  │
│  │  API Call: GET /api/users/me                                           │  │
│  │  Header:   Authorization: Bearer eyJhbGci...                          │  │
│  │       ↓                                                                │  │
│  │  JwtAuthenticationFilter → validate JWT → set SecurityContext          │  │
│  │       ↓                                                                │  │
│  │  AuthorizationFilter → check role → allow or 403                      │  │
│  │       ↓                                                                │  │
│  │  Controller → Service → Repository → DB                               │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Flow A: Local Login (step-by-step)

```
Client                                              Server
  │                                                    │
  │  POST /auth/login                                  │
  │  { "email": "user@example.com",                    │
  │    "password": "user123" }                         │
  │ ─────────────────────────────────────────────────► │
  │                                                    │
  │                           AuthController.login()
  │                           AuthService.login()
  │                             check: provider == LOCAL? ✓
  │                           AuthenticationManager.authenticate()
  │                             DaoAuthenticationProvider:
  │                               UserDetailsService.loadUserByUsername()
  │                                 → DB: SELECT * FROM users WHERE email=?
  │                               passwordEncoder.matches("user123", storedHash)
  │                                 → BCrypt comparison → match ✓
  │                           JwtService.generateAccessToken(userDetails)
  │                             → builds JWT: sub=email, role, iat, exp
  │                             → signs with HMAC-SHA256 + secret key
  │                           RefreshTokenService.createRefreshToken(user)
  │                             → UUID.randomUUID() stored in DB
  │                                                    │
  │  ◄─────────────────────────────────────────────── │
  │  HTTP 200 OK                                       │
  │  {                                                 │
  │    "accessToken":  "eyJhbGci...",  ← JWT (15 min) │
  │    "refreshToken": "uuid-string",  ← opaque (7d)  │
  │    "provider": "LOCAL",                            │
  │    "role": "ROLE_USER"                             │
  │  }                                                 │
```

---

## Flow B: OAuth2 Social Login (full redirect dance)

```
Client (Browser)                     Server                     Google
  │                                     │                          │
  │  GET /oauth2/authorization/google   │                          │
  │ ───────────────────────────────────►│                          │
  │                                     │  Build Google auth URL:  │
  │                                     │  client_id, scope,       │
  │                                     │  redirect_uri, state     │
  │  ◄─────────────────────────────────  │  302 Redirect            │
  │                                     │                          │
  │  GET accounts.google.com/o/oauth2/auth?...                     │
  │ ────────────────────────────────────────────────────────────── ►│
  │                                                                 │
  │  User sees Google consent screen, approves                      │
  │                                                                 │
  │  GET /login/oauth2/code/google?code=AUTH_CODE&state=...        │
  │ ◄──────────────────────────────────────────────────────────────  │
  │ ───────────────────────────────────►│                          │
  │                                     │                          │
  │                                     │  POST (server-to-server) │
  │                                     │ ────────────────────────►│
  │                                     │  exchange code for       │
  │                                     │  access_token            │
  │                                     │ ◄──────────────────────── │
  │                                     │                          │
  │                                     │  GET /userinfo           │
  │                                     │ ────────────────────────►│
  │                                     │  { sub, name, email,     │
  │                                     │    picture }             │
  │                                     │ ◄──────────────────────── │
  │                                     │                          │
  │                                     │  CustomOAuth2UserService.loadUser()
  │                                     │    OAuth2UserInfoFactory → GoogleOAuth2UserInfo
  │                                     │    findByProviderAndProviderId → existing user?
  │                                     │      YES → update name/picture
  │                                     │      NO  → check email → create new user
  │                                     │
  │                                     │  OAuth2SuccessHandler:
  │                                     │    JwtService.generateAccessToken()
  │                                     │    RefreshTokenService.createRefreshToken()
  │                                     │    Build redirect URL with tokens
  │                                     │
  │  GET http://localhost:3000/oauth2/callback
  │     ?accessToken=eyJhbGci...
  │     &refreshToken=uuid-abc123
  │ ◄───────────────────────────────────  │  302 Redirect to frontend
  │
  │  Frontend stores tokens, strips URL params
  │  All subsequent API calls use:
  │  Authorization: Bearer eyJhbGci...
```

---

## Flow C: Token Refresh

```
Client                                              Server
  │                                                    │
  │  (Access token expired — 401 received)             │
  │                                                    │
  │  POST /auth/refresh                                │
  │  { "refreshToken": "uuid-abc123" }                 │
  │ ─────────────────────────────────────────────────► │
  │                                                    │
  │                           RefreshTokenService.findAndValidate()
  │                             → DB: SELECT * FROM refresh_tokens WHERE token=?
  │                             → found? → check isExpired()
  │                           user = refreshToken.getUser()
  │                           check user.isActive() ← kill switch
  │                           RefreshTokenService.rotateRefreshToken()
  │                             → DELETE old token from DB
  │                             → INSERT new UUID token
  │                           JwtService.generateAccessToken(userDetails)
  │                             → new 15-min JWT
  │                                                    │
  │  ◄─────────────────────────────────────────────── │
  │  HTTP 200                                          │
  │  {                                                 │
  │    "accessToken":  "eyJhbGci... NEW",              │
  │    "refreshToken": "uuid-xyz789 NEW"               │
  │  }                                                 │
  │                                                    │
  │  ⚠️ Client MUST replace BOTH stored tokens!        │
```

---

## Flow D: Logout

```
Client                                              Server
  │                                                    │
  │  POST /auth/logout                                 │
  │  Authorization: Bearer eyJhbGci...                 │
  │ ─────────────────────────────────────────────────► │
  │                                                    │
  │                           JwtAuthenticationFilter validates JWT
  │                           SecurityContext set with user's email
  │                           AuthController.logout()
  │                           AuthService.logout(email)
  │                             → DB: DELETE FROM refresh_tokens WHERE user=?
  │                                                    │
  │  ◄─────────────────────────────────────────────── │
  │  HTTP 204 No Content                               │
  │                                                    │
  │  Access token still technically valid for ≤15 min  │
  │  but: no refresh token → cannot get new access tokens
  │  Effective logout for practical purposes           │
```

---

## API Endpoints Reference

### Auth Endpoints (Public)

| Method | URL | Body | Response |
|--------|-----|------|----------|
| POST | `/auth/register` | `name, email, password` | 201 + `TokenResponse` |
| POST | `/auth/login` | `email, password` | 200 + `TokenResponse` |
| POST | `/auth/refresh` | `refreshToken` | 200 + new `TokenResponse` |
| POST | `/auth/logout` | (none) — needs JWT header | 204 |

### Social Login (Browser/Redirect — No Request Body)

| Method | URL | What it does |
|--------|-----|-------------|
| GET | `/oauth2/authorization/google` | Redirects browser to Google consent |
| GET | `/oauth2/authorization/github` | Redirects browser to GitHub consent |
| GET | `/login/oauth2/code/google` | Google's callback (handled by Spring) |
| GET | `/login/oauth2/code/github` | GitHub's callback (handled by Spring) |

### User Endpoints (JWT Required)

| Method | URL | Role | Description |
|--------|-----|------|-------------|
| GET | `/api/users/me` | Any | Own profile |
| PUT | `/api/users/me` | Any | Update own name |
| GET | `/api/users/all` | ADMIN | List all users |
| GET | `/api/users/{id}` | ADMIN | Get user by ID |
| DELETE | `/api/users/{id}` | ADMIN | Deactivate user |

---

## How to Get OAuth2 Credentials

### Google
1. Go to https://console.cloud.google.com
2. Create/select a project
3. APIs & Services → Credentials → Create OAuth 2.0 Client ID
4. Application type: **Web application**
5. Authorized redirect URIs: `http://localhost:8080/login/oauth2/code/google`
6. Copy **Client ID** and **Client Secret** to `application.properties`

### GitHub
1. Go to https://github.com/settings/developers
2. OAuth Apps → **New OAuth App**
3. Homepage URL: `http://localhost:8080`
4. Authorization callback URL: `http://localhost:8080/login/oauth2/code/github`
5. Copy **Client ID** and generate + copy **Client Secret** to `application.properties`

---

## How to Run

```bash
cd oauth2-api
mvn spring-boot:run

# App: http://localhost:8080
# H2 Console: http://localhost:8080/h2-console
#   JDBC URL:  jdbc:h2:mem:oauth2db
#   Username:  sa
#   Password:  (empty)
```

---

## Testing with curl

### 1. Register a local account
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","password":"alice123"}'
```

### 2. Login with local account
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'
# Copy accessToken and refreshToken from the response
```

### 3. Access protected endpoint with JWT
```bash
curl -X GET http://localhost:8080/api/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. Update your profile
```bash
curl -X PUT http://localhost:8080/api/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Name"}'
```

### 5. Refresh expired access token
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
# Returns NEW accessToken and NEW refreshToken — replace both!
```

### 6. Logout
```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
# Returns 204. refreshToken is now deleted from DB.
```

### 7. Test error cases
```bash
# No token → 401
curl http://localhost:8080/api/users/me

# Wrong role → 403
curl http://localhost:8080/api/users/all \
  -H "Authorization: Bearer USER_ROLE_TOKEN"

# Tampered token → 401
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer TAMPERED_TOKEN_HERE"

# Refresh with used/invalid token → 401
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"fake-token"}'
```

### 8. Test social login (in browser)
```bash
# Open in a browser (not curl — needs real redirect + cookie handling):
http://localhost:8080/oauth2/authorization/google
http://localhost:8080/oauth2/authorization/github

# After approval, browser lands on:
# http://localhost:3000/oauth2/callback?accessToken=...&refreshToken=...
# Frontend reads tokens from URL, stores them, strips the URL
```

---

## Pre-Seeded Users

| Email | Password | Role | Provider |
|-------|----------|------|----------|
| admin@example.com | admin123 | ROLE_ADMIN | LOCAL |
| user@example.com | user123 | ROLE_USER | LOCAL |

---

## Key Design Decisions (Interview-Ready)

### Why issue our own JWT after OAuth2 login?
Google/GitHub give us an OAuth2 session — browser-based, stateful.
Our REST API is stateless — Bearer token based.
After OAuth2 success, we immediately issue our own short-lived JWT so:
- All subsequent API calls are identical (same Bearer token format)
- Mobile apps and React/Vue frontends work the same way
- No OAuth2 dependency after the initial login

### Why store refresh tokens in DB (not as JWT)?
We WANT them to be revocable. JWT refresh tokens can't be invalidated before expiry.
An opaque UUID in DB can be deleted instantly — that's how logout works.

### Why refresh token rotation?
Each use of a refresh token deletes it and creates a new one.
If a token is stolen and used by an attacker, the real user's next refresh fails
(their copy is now stale) — alerting them to a potential breach.

### How does logout work with JWT?
The short access token (~15 min) expires naturally — we can't revoke it early without a denylist.
The refresh token is deleted from DB immediately.
Effective logout: user cannot get new access tokens. Old one expires in ≤15 min.
For instant full invalidation: add access token `jti` (JWT ID) to a Redis denylist.

### How does the OAuth2 "find or create" logic work?
1. First: look up by `(provider, providerId)` — returning OAuth2 user
2. Second: look up by email — existing LOCAL account (link it to OAuth2)
3. Third: create brand new user from OAuth2 profile data

---

## Quick Comparison: All Three Projects

| Feature | Basic Auth Project | JWT Project | OAuth2 Project |
|---|---|---|---|
| Login mechanism | `Authorization: Basic b64` | `POST /auth/login` → JWT | Local + Google/GitHub |
| Token type | None (creds every request) | JWT (stateless) | JWT (after OAuth2 dance) |
| Refresh token | N/A | No | Yes (DB-backed, rotated) |
| Logout | N/A | Access token expires | Delete refresh token |
| Social login | No | No | Yes (Google, GitHub) |
| DB call per request | Yes (UserDetailsService) | Yes (kill-switch check) | Yes (kill-switch check) |
| Session | No | No | No (STATELESS) |

---

## Next Steps to Build On This

1. **Email Verification** — send a link on register, block login until verified
2. **Password Reset** — time-limited reset token via email (JavaMailSender)
3. **Facebook / Apple Login** — add to `AuthProvider` enum + `OAuth2UserInfoFactory`
4. **Redis Token Denylist** — instant access token invalidation on logout
5. **HttpOnly Cookie for Refresh Token** — more secure than body/localStorage
6. **Flyway DB Migrations** — version-controlled schema changes for production DB
7. **Rate Limiting** — protect /auth/login from brute-force with Bucket4j
8. **2FA / TOTP** — Google Authenticator support with a TOTP library
