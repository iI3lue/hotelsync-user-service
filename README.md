# HotelSync — User Service

Microservicio de identidad y personal de HotelSync: registro, login local, login federado con Google vía Auth0, sesiones con refresh tokens, recuperación de contraseña, consentimiento de tratamiento de datos (Ley 1581) y gestión de staff por hotel.

- **Producción:** https://hotelsync-user-service.onrender.com
- **Puerto local:** 3003
- **Base de datos:** `user_db` (PostgreSQL 16)

## Responsabilidad

| Hace | No hace |
| --- | --- |
| Autenticar usuarios y emitir JWT HS256 | Autorizar reglas de negocio de otros servicios |
| Gestionar roles (`SUPER_ADMIN`, `MANAGER`, `RECEPTIONIST`, `HOUSEKEEPER`, `GUEST`) | Guardar reservas, folios o pagos |
| Administrar personal global y por hotel | Ser dueño de datos de huéspedes más allá de la cuenta |
| Validar identidades federadas de Auth0 | Gestionar inventario |

## Tecnologías

Node.js ≥20 · TypeScript · Express · Prisma · PostgreSQL 16 · Zod · `jsonwebtoken` · Auth0 (JWKS) · RabbitMQ no requerido.

## Arquitectura interna

`Route → Controller → Service → Prisma`. Todo borde valida con Zod y responde errores `AppError`. El JWT se firma con `AUTH_JWT_SECRET` (HS256, audiencia `hotelsync-api`) y se comparte con el resto de servicios; los refresh tokens viven hasheados en `RefreshSession`. El login federado verifica el `id_token` de Auth0 contra su JWKS y exige `nonce`.

## Endpoints

| Método | Ruta | Auth | Descripción |
| --- | --- | --- | --- |
| GET | `/health` | — | Estado del servicio |
| POST | `/v1/auth/register` | — | Registro de huésped (exige `terms_accepted: true`) |
| POST | `/v1/auth/login` | — | Login local (email + contraseña) |
| POST | `/v1/auth/federated` | — | Login con `id_token` de Auth0/Google |
| POST | `/v1/auth/refresh` | Refresh token | Renueva access token |
| POST | `/v1/auth/logout` | Refresh token | Revoca la sesión |
| POST | `/v1/auth/password/forgot` | — | Solicita recuperación |
| POST | `/v1/auth/password/code` | — | Solicita código de un solo uso |
| POST | `/v1/auth/password/reset` | Código | Cambia la contraseña |
| GET | `/v1/users/me` | JWT | Perfil propio |
| PATCH | `/v1/users/me` | JWT | Actualiza perfil |
| POST | `/v1/users/me/consent` | JWT | Acepta el tratamiento de datos (una vez, idempotente) |
| DELETE | `/v1/users/me` | JWT | Baja de cuenta (falla si hay reservas activas) |
| GET | `/v1/users/internal/:id` | `x-loyalty-key` | Datos mínimos para loyalty-service |
| POST | `/v1/admin/users` | JWT + SUPER_ADMIN | Crea staff global |
| GET | `/v1/admin/users` | JWT | Lista staff |
| PATCH | `/v1/admin/users/:id` | JWT + SUPER_ADMIN | Actualiza staff |
| POST | `/v1/staff` | JWT | Alta de staff |
| GET | `/v1/staff` | JWT | Lista staff |
| PATCH | `/v1/staff/:id` | JWT | Actualiza staff |
| POST | `/v1/hotels/:hotelId/staff` | JWT | Alta de personal del hotel |
| GET | `/v1/hotels/:hotelId/staff` | JWT | Personal del hotel |
| PATCH | `/v1/hotels/:hotelId/staff/:userId` | JWT | Activa/desactiva personal |

## Modelo de datos

Tablas: `User`, `PasswordResetToken`, `RoleAssignment`, `ExternalIdentity`, `RefreshSession`.

Migraciones en `prisma/migrations` (5). El seed crea un `SUPER_ADMIN` **solo** si existen `BOOTSTRAP_ADMIN_EMAIL` y `BOOTSTRAP_ADMIN_PASSWORD`; si no, no inserta nada. El consentimiento de datos se guarda en `User.terms_accepted_at`.

## Comunicación

- **REST saliente:** `GET {BOOKING_SERVICE_URL}/bookings/by-user/:userId/has-active` (header `x-user-key`) antes de borrar una cuenta.
- **Clave entrante:** loyalty-service consulta `/v1/users/internal/:id` con `x-loyalty-key`.
- **JWT:** el token emitido aquí lo verifican todos los servicios con el mismo `AUTH_JWT_SECRET`.

## Variables de entorno

| Variable | Obligatoria | Descripción |
| --- | --- | --- |
| `NODE_ENV` | No | `development` / `production` |
| `PORT` | No | Puerto HTTP (default 3003) |
| `DATABASE_URL` | Sí | PostgreSQL de `user_db` |
| `AUTH_JWT_SECRET` | Sí | HS256 compartido (mín. 32 caracteres) |
| `AUTH0_DOMAIN` | Para login Google | Dominio del tenant |
| `AUTH0_CLIENT_ID` | Para login Google | Audiencia del `id_token` |
| `PASSWORD_RESET_BASE_URL` | No | Enlace enviado en la recuperación |
| `MAILER_PROVIDER` | No | `log` (default, imprime en consola) o `smtp` |
| `PASSWORD_RESET_DEMO_CODE` | No | Solo con `MAILER_PROVIDER=log`: `true` expone el código y el enlace de reset (demo, apagado por defecto) |
| `BOOKING_SERVICE_URL` | Sí | Base de booking-service |
| `BOOKING_SERVICE_KEY` | Sí | Clave interna `x-user-key` |
| `LOYALTY_SERVICE_KEY` | Sí | Clave que valida `/users/internal/:id` |
| `BOOTSTRAP_ADMIN_EMAIL` | No | Solo seed |
| `BOOTSTRAP_ADMIN_PASSWORD` | No | Solo seed |

Copiar `.env.example` a `.env` y completar los valores.

El código de recuperación solo se expone en la respuesta de `/v1/auth/password/code` cuando `MAILER_PROVIDER=log` **y** `PASSWORD_RESET_DEMO_CODE=true`; con `smtp` o sin el opt-in el código viaja por email y nunca sale en la respuesta.

## Ejecución local

```bash
npm install
cp .env.example .env
npx prisma migrate deploy
npm run seed
npm run dev                 # http://localhost:3003
```

## Despliegue

Render (Oregon, free): build `npm ci && npx prisma generate && npm run build`; start `npx prisma migrate deploy && npm start`; Neon `user_db`. El callback de Auth0 debe apuntar al front (`APP_BASE_URL`), no a este servicio. El plan free duerme a los 15 minutos.

## Pruebas y verificación

```bash
npm test
npm run lint
curl https://hotelsync-user-service.onrender.com/health
```

## Respaldo de base de datos

```bash
pg_dump "$DATABASE_URL" -Fc -f user_db.dump
pg_restore --clean --if-exists -d "$DATABASE_URL" user_db.dump
```

## Estructura

```
src/{routes,controllers,services,validators,middleware,lib}
prisma/{schema.prisma,seed.ts,migrations}
tests/
```
