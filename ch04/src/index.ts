import "dotenv/config";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { serve } from "@hono/node-server";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type CredentialDeviceType,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from "@simplewebauthn/server";
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

const app = new Hono();

const requiredEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
};

const rpID = requiredEnv("RP_ID");
const rpName = requiredEnv("RP_NAME");
const rpOrigin = requiredEnv("RP_ORIGIN");

type User = {
  id: string;
  username: string;
  userHandle: Uint8Array;
  passwordHash: string;
};

type StoredCredential = {
  userId: string;
  name: string;
  createdAt: string;
  credential: WebAuthnCredential;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
};

const hashPassword = (password: string): string => {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
};

const verifyPassword = (password: string, stored: string): boolean => {
  const [salt, key] = stored.split(":");
  if (!salt || !key) {
    return false;
  }
  const hashBuffer = scryptSync(password, salt, 64);
  const keyBuffer = Buffer.from(key, "hex");
  return timingSafeEqual(hashBuffer, keyBuffer);
};

const users = new Map<string, User>();
const credentials = new Map<string, StoredCredential>();
const challenges = new Set<string>();
const sessions = new Map<string, string>();

const seedUser: User = {
  id: "user-alice",
  username: "alice",
  userHandle: new TextEncoder().encode("user-alice"),
  passwordHash: hashPassword("password123"),
};
users.set(seedUser.id, seedUser);

const issueSession = (c: Context, userId: string): void => {
  const sessionId = randomBytes(32).toString("base64url");
  sessions.set(sessionId, userId);
  setCookie(c, "session_id", sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
  });
};

const getCurrentUser = (c: Context): User | undefined => {
  const sessionId = getCookie(c, "session_id");
  if (!sessionId) {
    return undefined;
  }
  const userId = sessions.get(sessionId);
  if (!userId) {
    return undefined;
  }
  return users.get(userId);
};

app.get("/", (c) => {
  return c.html(`<!doctype html>
<html lang="ja">
  <head>
    <meta charset="utf-8" />
    <title>Passkey Practical Hands-on</title>
  </head>
  <body>
    <h1>Passkey Practical Hands-on (ch04)</h1>

    <section>
      <h2>1. ログイン（パスワード併用 + Conditional UI）</h2>
      <div>
        <input
          id="username"
          name="username"
          type="text"
          autocomplete="username webauthn"
          placeholder="username (空欄時は alice)"
        />
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="current-password"
          placeholder="password (初期値: password123)"
          value="password123"
        />
      </div>
      <div>
        <button id="password-login-btn" type="button">Login with Password</button>
        <button id="passkey-login-btn" type="button">Login with Passkey</button>
        <button id="me-btn" type="button">Check Session (/me)</button>
        <button id="logout-btn" type="button">Logout</button>
      </div>
    </section>

    <section>
      <h2>2. パスキーの管理（要ログイン）</h2>
      <div>
        <input
          id="passkey-name"
          type="text"
          placeholder="パスキーの名前 (例: MacBook Touch ID)"
        />
        <button id="register-btn" type="button">Add Passkey</button>
        <button id="list-btn" type="button">List Passkeys (/credentials)</button>
      </div>
      <ul id="credential-list"></ul>
    </section>

    <h2>実行結果</h2>
    <pre id="output">操作してください</pre>

    <script>
      const output = document.getElementById("output");
      const credentialList = document.getElementById("credential-list");
      let conditionalAbortController = null;

      const show = (data) => {
        output.textContent = JSON.stringify(data, null, 2);
      };

      const refreshCredentials = async () => {
        credentialList.innerHTML = "";
        const res = await fetch("/credentials");
        if (!res.ok) {
          return;
        }
        const data = await res.json();
        for (const item of data.credentials) {
          const li = document.createElement("li");
          li.textContent = \`\${item.name} (\${item.credentialDeviceType}, backedUp: \${item.credentialBackedUp}) [\${item.id}] \`;
          const delBtn = document.createElement("button");
          delBtn.type = "button";
          delBtn.textContent = "Delete";
          delBtn.addEventListener("click", async () => {
            const delRes = await fetch(\`/credentials/\${encodeURIComponent(item.id)}\`, {
              method: "DELETE",
            });
            show(await delRes.json());
            await refreshCredentials();
          });
          li.appendChild(delBtn);
          credentialList.appendChild(li);
        }
      };

      const startConditionalUI = async () => {
        if (
          typeof PublicKeyCredential === "undefined" ||
          typeof PublicKeyCredential.isConditionalMediationAvailable !== "function"
        ) {
          return;
        }
        const available = await PublicKeyCredential.isConditionalMediationAvailable();
        if (!available) {
          return;
        }

        try {
          if (conditionalAbortController) {
            conditionalAbortController.abort();
          }
          conditionalAbortController = new AbortController();

          const optionsRes = await fetch("/login/options", { method: "POST" });
          const optionsJSON = await optionsRes.json();
          const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsJSON);

          const credential = await navigator.credentials.get({
            publicKey,
            mediation: "conditional",
            signal: conditionalAbortController.signal,
          });
          const authenticationResponse = credential.toJSON();

          const verifyRes = await fetch("/login/verify", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ response: authenticationResponse }),
          });
          const verifyData = await verifyRes.json();
          show({ step: "conditional-login", verifyData });
          await refreshCredentials();
        } catch (err) {
          if (err.name !== "AbortError") {
            show({ error: String(err) });
          }
        }
      };

      document.getElementById("password-login-btn").addEventListener("click", async () => {
        const username = document.getElementById("username").value.trim() || "alice";
        const password = document.getElementById("password").value;
        const res = await fetch("/login/password", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
        show(await res.json());
        await refreshCredentials();
      });

      document.getElementById("passkey-login-btn").addEventListener("click", async () => {
        try {
          if (conditionalAbortController) {
            conditionalAbortController.abort();
            conditionalAbortController = null;
          }
          const optionsRes = await fetch("/login/options", { method: "POST" });
          const optionsJSON = await optionsRes.json();

          const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsJSON);
          const credential = await navigator.credentials.get({ publicKey });
          const authenticationResponse = credential.toJSON();

          const verifyRes = await fetch("/login/verify", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ response: authenticationResponse }),
          });
          const verifyData = await verifyRes.json();
          show({ step: "passkey-login", verifyData });
          await refreshCredentials();
        } catch (err) {
          show({ error: String(err) });
        }
      });

      document.getElementById("register-btn").addEventListener("click", async () => {
        try {
          if (conditionalAbortController) {
            conditionalAbortController.abort();
            conditionalAbortController = null;
          }
          const name = document.getElementById("passkey-name").value.trim() || "My Passkey";
          const optionsRes = await fetch("/register/options", { method: "POST" });
          if (!optionsRes.ok) {
            show(await optionsRes.json());
            return;
          }
          const optionsJSON = await optionsRes.json();

          const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJSON);
          const credential = await navigator.credentials.create({ publicKey });
          const registrationResponse = credential.toJSON();

          const verifyRes = await fetch("/register/verify", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ name, response: registrationResponse }),
          });
          const verifyData = await verifyRes.json();
          show({ step: "register", verifyData });
          await refreshCredentials();
        } catch (err) {
          show({ error: String(err) });
        }
      });

      document.getElementById("list-btn").addEventListener("click", async () => {
        const res = await fetch("/credentials");
        show(await res.json());
        await refreshCredentials();
      });

      document.getElementById("me-btn").addEventListener("click", async () => {
        const res = await fetch("/me");
        show(await res.json());
      });

      document.getElementById("logout-btn").addEventListener("click", async () => {
        const res = await fetch("/logout", { method: "POST" });
        show(await res.json());
        credentialList.innerHTML = "";
        await startConditionalUI();
      });

      startConditionalUI();
    </script>
  </body>
</html>`);
});

app.post("/login/password", async (c) => {
  const { username, password } = await c.req.json<{
    username?: string;
    password?: string;
  }>();

  if (!username || !password) {
    return c.json({ error: "username and password are required" }, 400);
  }

  const user = Array.from(users.values()).find((u) => u.username === username);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return c.json({ error: "invalid username or password" }, 401);
  }

  issueSession(c, user.id);

  return c.json({
    loggedIn: true,
    method: "password",
    user: { id: user.id, username: user.username },
  });
});

app.post("/register/options", async (c) => {
  const user = getCurrentUser(c);
  if (!user) {
    return c.json({ error: "login is required to add a passkey" }, 401);
  }

  const userCredentials = Array.from(credentials.values()).filter(
    (item) => item.userId === user.id,
  );

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.username,
    userID: new Uint8Array(user.userHandle),
    excludeCredentials: userCredentials.map((item) => ({
      id: item.credential.id,
      transports: item.credential.transports,
    })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
  });

  challenges.add(options.challenge);

  return c.json(options);
});

app.post("/register/verify", async (c) => {
  const user = getCurrentUser(c);
  if (!user) {
    return c.json({ error: "login is required to add a passkey" }, 401);
  }

  const { name, response } = await c.req.json<{
    name?: string;
    response?: RegistrationResponseJSON;
  }>();

  if (!response) {
    return c.json({ error: "response is required" }, 400);
  }

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: (challenge) => {
      if (!challenges.has(challenge)) {
        return false;
      }
      challenges.delete(challenge);
      return true;
    },
    expectedOrigin: rpOrigin,
    expectedRPID: rpID,
  });

  if (!verification.verified || !verification.registrationInfo) {
    return c.json({ verified: false }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } =
    verification.registrationInfo;

  const passkeyName = name?.trim() || "My Passkey";
  const createdAt = new Date().toISOString();

  credentials.set(credential.id, {
    userId: user.id,
    name: passkeyName,
    createdAt,
    credential,
    credentialDeviceType,
    credentialBackedUp,
  });

  return c.json({
    verified: true,
    credential: {
      id: credential.id,
      name: passkeyName,
      createdAt,
      credentialDeviceType,
      credentialBackedUp,
    },
  });
});

app.get("/credentials", (c) => {
  const user = getCurrentUser(c);
  if (!user) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const list = Array.from(credentials.values())
    .filter((item) => item.userId === user.id)
    .map((item) => ({
      id: item.credential.id,
      name: item.name,
      createdAt: item.createdAt,
      credentialDeviceType: item.credentialDeviceType,
      credentialBackedUp: item.credentialBackedUp,
    }));

  return c.json({ credentials: list });
});

app.delete("/credentials/:id", (c) => {
  const user = getCurrentUser(c);
  if (!user) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const id = c.req.param("id");
  const stored = credentials.get(id);

  if (!stored || stored.userId !== user.id) {
    return c.json({ error: "credential not found" }, 404);
  }

  credentials.delete(id);

  return c.json({ deleted: true, id });
});

app.post("/login/options", async (c) => {
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "preferred",
  });

  challenges.add(options.challenge);

  return c.json(options);
});

app.post("/login/verify", async (c) => {
  const { response } = await c.req.json<{
    response?: AuthenticationResponseJSON;
  }>();

  if (!response) {
    return c.json({ error: "response is required" }, 400);
  }

  const stored = credentials.get(response.id);
  if (!stored) {
    return c.json({ error: "credential not found" }, 400);
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: (challenge) => {
      if (!challenges.has(challenge)) {
        return false;
      }
      challenges.delete(challenge);
      return true;
    },
    expectedOrigin: rpOrigin,
    expectedRPID: rpID,
    credential: stored.credential,
  });

  if (!verification.verified) {
    return c.json({ verified: false }, 400);
  }

  stored.credential.counter = verification.authenticationInfo.newCounter;

  const user = users.get(stored.userId);
  if (!user) {
    return c.json({ error: "user not found" }, 400);
  }

  issueSession(c, user.id);

  return c.json({
    verified: true,
    method: "passkey",
    user: { id: user.id, username: user.username },
    usedCredential: {
      id: stored.credential.id,
      name: stored.name,
    },
  });
});

app.get("/me", (c) => {
  const user = getCurrentUser(c);
  if (!user) {
    return c.json({ loggedIn: false }, 401);
  }

  return c.json({
    loggedIn: true,
    user: { id: user.id, username: user.username },
  });
});

app.post("/logout", (c) => {
  const sessionId = getCookie(c, "session_id");
  if (sessionId) {
    sessions.delete(sessionId);
  }
  deleteCookie(c, "session_id", { path: "/" });
  return c.json({ loggedOut: true });
});

const port = Number(process.env.PORT ?? 3000);

serve({
  fetch: app.fetch,
  port,
});

console.log(`Server is running on http://localhost:${port}`);
