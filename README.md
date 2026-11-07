# Understanding Passkeys / WebAuthn / FIDO2 through Implementation ── Sample Code

This is the official sample code repository for the book *Understanding Passkeys, WebAuthn, and FIDO2 through Implementation: Building with TypeScript and Operating with Keycloak* ([Japanese edition on Amazon.co.jp](https://www.amazon.co.jp/dp/B0HQN3FDBC)).

---

## 📁 Directory Structure

```text
.
├── ch02/                # Chapter 2: Implementing passkeys yourself (minimal registration/authentication ceremonies)
├── ch04/                # Chapter 4: Raising it to production level (password coexistence, multiple key management, Conditional UI)
└── ch05/                # Chapter 5: Operating passkeys with Keycloak (authentication integration via an IdP, OIDC)
```

- **`ch02/`**: A minimal passkey registration/authentication ceremony built with Hono + `@simplewebauthn/server`. Experience usernameless login with discoverable credentials (resident keys) and session management.
- **`ch04/`**: A practical version that combines coexistence with existing password authentication, prevention of duplicate registration of the same authenticator (`excludeCredentials`), naming/listing/deleting multiple passkeys, and Conditional UI (`mediation: "conditional"`) that offers passkeys through autofill.
- **`ch05/`**: A production-style setup where passkey management is delegated to Keycloak 26.1 and the Hono app receives the authentication result (ID token) via OpenID Connect (OIDC). Includes a `compose.yml` for running Keycloak locally.

---

## 🚀 Quick Start

Move into the directory of the chapter you want to run, then install dependencies and start the server.  
**Google Chrome** is recommended for trying the samples (on macOS Safari, Conditional UI may not trigger on `http://localhost` due to how the OS autofill menu behaves in that environment).

### Running Chapter 2 (minimal implementation):

```bash
cd ch02
npm install

# Create .env
cp .env.example .env

npm run dev
```

After startup, open `http://localhost:3000` in Google Chrome and try "Register Passkey" followed by "Login with Passkey".

---

### Running Chapter 4 (production-level implementation):

```bash
cd ch04
npm install

# Create .env
cp .env.example .env

npm run dev
```

After startup, open `http://localhost:3000` in Google Chrome.
1. Log in with `alice` / `password123` by clicking "Login with Password"
2. Register an additional passkey with "Add Passkey" (you can also see duplicate registration being blocked)
3. After "Logout", click the username field and log in by selecting a passkey from Conditional UI (autofill)

> 💡 **Note**: If a `localhost` passkey created in Chapter 2 remains in your OS password manager, candidates may overlap. Deleting the existing `localhost` passkey from your OS Passwords app beforehand makes this smoother.

---

### Running Chapter 5 (Keycloak operation):

#### 1. Start Keycloak

```bash
cd ch05
docker compose up -d
```

After startup, open `http://localhost:8080` in your browser and log in to the admin console.
- **Username**: `admin`
- **Password**: `admin`

Following the book's steps, configure the realm (`passkey-book`), client (`passkey-book-app`), user (`alice`), the WebAuthn Passwordless policy, and the authentication flow (`browser-passkey`).

#### 2. Start the application

```bash
# Create .env
cp .env.example .env
# Edit OIDC_CLIENT_SECRET in .env with the value from the Keycloak admin console

npm install
npm run dev
```

After startup, open `http://localhost:3000` in your browser and click "Login with Keycloak (OIDC)". On first login you will register a passkey through a Required Action; from then on you can log in passwordlessly with your passkey.

---

## 🛠 Tech Stack

- **Runtime**: Node.js (v20+)
- **Language**: TypeScript
- **Web Framework**: [Hono](https://hono.dev/)
- **Server Adapter**: `@hono/node-server`
- **WebAuthn Library**: [@simplewebauthn/server](https://simplewebauthn.dev/)
- **Identity Provider**: Keycloak 26.1 (Docker)

---

## 📄 License

MIT License
