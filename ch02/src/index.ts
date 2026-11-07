import "dotenv/config";
import { randomBytes } from "node:crypto";
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
import { Hono } from "hono";
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
};

type StoredCredential = {
  userId: string;
  credential: WebAuthnCredential;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
};

const users = new Map<string, User>();
const credentials = new Map<string, StoredCredential>();
const challenges = new Set<string>();
const sessions = new Map<string, string>();

app.get("/", (c) => {
  return c.html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Passkey Hands-on</title>
  </head>
  <body>
    <h1>Passkey Hands-on</h1>

    <section>
      <h2>1. Register Passkey</h2>
      <input id="username" type="text" placeholder="username (e.g. alice)" />
      <button id="register-btn" type="button">Register Passkey</button>
    </section>

    <section>
      <h2>2. Passkey Authentication (Usernameless)</h2>
      <button id="login-btn" type="button">Login with Passkey</button>
      <button id="me-btn" type="button">Check Session (/me)</button>
      <button id="logout-btn" type="button">Logout</button>
    </section>

    <h2>Execution Result</h2>
    <pre id="output">Click a button to start</pre>

    <script>
      const output = document.getElementById("output");
      const show = (data) => {
        output.textContent = JSON.stringify(data, null, 2);
      };

      document.getElementById("register-btn").addEventListener("click", async () => {
        try {
          const username = document.getElementById("username").value.trim();
          const optionsRes = await fetch("/register/options", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ username }),
          });
          if (!optionsRes.ok) {
            show({ error: await optionsRes.text() });
            return;
          }
          const optionsJSON = await optionsRes.json();

          const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJSON);
          const credential = await navigator.credentials.create({ publicKey });
          const registrationResponse = credential.toJSON();

          const verifyRes = await fetch("/register/verify", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ username, response: registrationResponse }),
          });
          const verifyData = await verifyRes.json();
          show({
            step: "register",
            optionsJSON,
            registrationResponse,
            verifyData,
          });
        } catch (err) {
          show({ error: String(err) });
        }
      });

      document.getElementById("login-btn").addEventListener("click", async () => {
        try {
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
          show({
            step: "login",
            optionsJSON,
            authenticationResponse,
            verifyData,
          });
        } catch (err) {
          show({ error: String(err) });
        }
      });

      document.getElementById("me-btn").addEventListener("click", async () => {
        const res = await fetch("/me");
        show(await res.json());
      });

      document.getElementById("logout-btn").addEventListener("click", async () => {
        const res = await fetch("/logout", { method: "POST" });
        show(await res.json());
      });
    </script>
  </body>
</html>`);
});

app.post("/register/options", async (c) => {
  const { username } = await c.req.json<{ username?: string }>();
  if (!username) {
    return c.text("username is required", 400);
  }

  const userId = `user-${username}`;

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: username,
    userID: new TextEncoder().encode(userId),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
  });

  challenges.add(options.challenge);

  return c.json(options);
});

app.post("/register/verify", async (c) => {
  const { username, response } = await c.req.json<{
    username?: string;
    response?: RegistrationResponseJSON;
  }>();

  if (!username || !response) {
    return c.json({ error: "username and response are required" }, 400);
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

  const userId = `user-${username}`;
  const user: User = { id: userId, username };
  users.set(userId, user);

  credentials.set(credential.id, {
    userId,
    credential,
    credentialDeviceType,
    credentialBackedUp,
  });

  return c.json({
    verified: true,
    user,
    credentialId: credential.id,
    credentialDeviceType,
    credentialBackedUp,
  });
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
  const sessionId = randomBytes(32).toString("base64url");
  sessions.set(sessionId, stored.userId);

  setCookie(c, "session_id", sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
  });

  return c.json({
    verified: true,
    user,
    authenticationInfo: verification.authenticationInfo,
  });
});

app.get("/me", (c) => {
  const sessionId = getCookie(c, "session_id");
  if (!sessionId) {
    return c.json({ loggedIn: false }, 401);
  }

  const userId = sessions.get(sessionId);
  if (!userId) {
    return c.json({ loggedIn: false }, 401);
  }

  const user = users.get(userId);
  return c.json({ loggedIn: true, user });
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
