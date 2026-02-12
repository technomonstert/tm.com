# TM.com – Telecom Portal Prototype

**This is the Day 1 scaffold** for the full‑blown telecom web portal you requested. It contains:

- **Backend** (`backend/`) – a tiny Express server with health endpoint, JWT‑based auth stubs (register/login), bcrypt password hashing, and rate‑limiting.
- **Frontend** (`frontend/`) – a static HTML landing page (served by Express) that displays the AI‑generated logo and a simple login form.
- **Docker‑Compose** (`docker-compose.yml`) that brings up PostgreSQL, Redis, the backend API, and the static front‑end server.
- **`.env.example`** – all environment variables you must set (database credentials, JWT secret, Stripe test keys, etc.).
- **`setup.sh`** – one‑line installer that installs Docker (if missing), copies the `.env.example` to `.env`, and runs `docker compose up -d`.
- **`postman_collection.json`** – minimal API contract (health, register, login) for early testing.

You can clone the repository, run `./setup.sh`, then open `http://localhost:3000` to see the landing page and register a user.

Further development (plans catalogue, Stripe checkout, admin UI, etc.) will be added day by day.
