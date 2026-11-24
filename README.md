# Student Results Portal (with backend)

Node.js + SQLite. No `npm install` needed. Requires **Node 22.13 or newer** (check with `node -v`).

## Run it
1. Open this folder in VS Code, then open the terminal (Terminal > New Terminal).
2. Run: `npm start`
3. The first run prints the **admin temporary password** and the **sample students' temporary passwords**. Copy them; they are shown once.
4. Open http://localhost:3000 (not Live Server: the backend serves the pages itself).

Everyone must choose a new password (8+ characters) the first time they sign in.

## Commands
- `npm start`: run the server
- `npm run reset`: wipe the database and start again with sample data
- `npm run empty`: wipe the database and start with only the admin account (use this for real data)

## Settings (environment variables)
- `PORT` (default 3000), `HOST` (default 127.0.0.1, this computer only)
- `ADMIN_PASSWORD`: set the first admin temporary password instead of a random one
- `COOKIE_SECURE=true`: set this when serving over HTTPS
- `TRUST_PROXY=true`: only if behind a reverse proxy you control

## What the server does
- Passwords stored as salted scrypt hashes; never sent to the browser
- Random session tokens in an HttpOnly, SameSite=Strict cookie (8 hours); only a hash of the token is stored
- Staff-only actions refused for students by the server; students only receive their own data
- Login lockout (5 wrong tries = 60 seconds), cross-site request blocking, input validation, parameterised SQL
- Content-Security-Policy and other security headers

## Before using it with real students
- Serve it over HTTPS (for example behind Caddy or nginx) and set `COOKIE_SECURE=true`
- Back up `data.db` regularly
- Keep `data.db` out of version control
