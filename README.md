# Phone Book

A phone book with user accounts: Flask REST API + web UI, PostgreSQL storage, packaged with Docker.
Each user only sees and edits their own contacts.

## Run with Docker
```bash
cp .env.example .env        # set POSTGRES_PASSWORD and SECRET_KEY
docker compose up --build -d
```
Open http://localhost:8000, register, and add contacts.

Generate a secret key with `python -c "import secrets; print(secrets.token_hex(32))"`.

## Run tests
Tests run against a real Postgres (the compose `db` service):
```bash
docker run --rm --network phonebook_default -e DATABASE_URL=postgresql://phonebook:phonebook@db:5432/phonebook -e SECRET_KEY=test -v "$PWD:/src" -w /src phonebook:latest python test_app.py
```

## Configuration
| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string |
| `SECRET_KEY` | Signs auth tokens (required) |
| `TOKEN_MAX_AGE` | Token lifetime in seconds (default 7 days) |
| `DB_POOL_SIZE` | Max DB connections per worker (default 10) |

## API
Authenticate with `Authorization: Bearer <token>` (from register or login).

| Method | Path | Body |
|---|---|---|
| POST | `/api/auth/register` | `{"email","password"}` → `{token}` |
| POST | `/api/auth/login` | `{"email","password"}` → `{token}` |
| GET | `/api/auth/me` | – |
| GET | `/api/contacts?q=ali` | – |
| GET | `/api/contacts/{id}` | – |
| POST | `/api/contacts` | `{"name","phone","email?"}` |
| PUT | `/api/contacts/{id}` | any of name/phone/email |
| DELETE | `/api/contacts/{id}` | – |
| GET | `/health` | – |

## Design notes
- Passwords are hashed with scrypt (werkzeug); tokens are signed and expire (itsdangerous).
- The app is stateless: no local files or sessions, so you can run many copies behind a load balancer.
- Connection pooling via `psycopg_pool`; schema creation is guarded by a Postgres advisory lock so multiple workers can start at once.

## Get it
- Source: https://github.com/devsan95/phonebook
- Image: https://hub.docker.com/r/santoshkumar55264/phonebook

```bash
docker pull santoshkumar55264/phonebook:latest
```
To run the published image instead of building locally, replace `build: .` with
`image: santoshkumar55264/phonebook:latest` in `docker-compose.yml`.

For a public deployment, use a managed Postgres (Cloud SQL, RDS, Neon, Supabase) and set `DATABASE_URL` and `SECRET_KEY` as secrets on your host.
