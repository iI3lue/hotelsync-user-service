# hotelsync-user-service

HotelSync user microservice (identity, auth, staff). Part of the HotelSync platform — one repo per microservice.

## Endpoints

- `POST /v1/auth/register` — public guest registration
- `POST /v1/auth/login` — login (email + password)
- `POST /v1/auth/refresh` — rotate refresh token
- `POST /v1/auth/logout` — revoke refresh token
- `POST /v1/auth/federated` — login with Auth0 (Google) id token
- `GET /users/me` — current user (Bearer access token)
- `POST /v1/admin/users` — create staff user (SUPER_ADMIN)
- `GET /v1/admin/users` — list users (SUPER_ADMIN)
- `POST /v1/hotels/:hotelId/staff` — create staff for a hotel (MANAGER of that hotel)
- `GET /health` — health check

Auth is HS256 (`AUTH_JWT_SECRET`, shared with the other services). Google login goes through Auth0 (`AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`).

## Local dev

```bash
cp .env.example .env   # fill in real values, never commit them
npm ci
npx prisma generate
npx prisma migrate deploy
npm run dev            # :3003
npm test
```

## Seed

`npm run seed` creates the bootstrap `SUPER_ADMIN` from `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` (skips if already exists).
