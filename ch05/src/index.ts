import "dotenv/config";
import { createHash, randomBytes } from "node:crypto";
import { serve } from "@hono/node-server";
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

const issuerUrl = requiredEnv("OIDC_ISSUER_URL").replace(/\/+$/, "");
const clientId = requiredEnv("OIDC_CLIENT_ID");
const clientSecret = requiredEnv("OIDC_CLIENT_SECRET");
const redirectUri = requiredEnv("OIDC_REDIRECT_URI");
const postLogoutRedirectUri = requiredEnv("OIDC_POST_LOGOUT_REDIRECT_URI");

type OpenIdConfiguration = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint: string;
};

type IdTokenClaims = {
  sub: string;
  preferred_username?: string;
  email?: string;
  acr?: string;
  auth_time?: number;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
};

type SessionData = {
  idToken: string;
  claims: IdTokenClaims;
};

const sessions = new Map<string, SessionData>();

const fetchDiscovery = async (): Promise<OpenIdConfiguration> => {
  const res = await fetch(`${issuerUrl}/.well-known/openid-configuration`);
  if (!res.ok) {
    throw new Error(`Failed to fetch OIDC discovery: ${res.status}`);
  }
  return (await res.json()) as OpenIdConfiguration;
};

app.get("/", (c) => {
  return c.html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Keycloak Passkey OIDC Hands-on</title>
  </head>
  <body>
    <h1>Keycloak Passkey OIDC Hands-on (ch05)</h1>
    <div>
      <a href="/auth/login"><button type="button">Login with Keycloak (OIDC)</button></a>
      <button id="me-btn" type="button">Check Session (/me)</button>
      <a href="/auth/logout"><button type="button">Logout</button></a>
    </div>
    <h2>Execution Result</h2>
    <pre id="output">Loading...</pre>
    <script>
      const output = document.getElementById("output");
      const checkSession = async () => {
        const res = await fetch("/me");
        output.textContent = JSON.stringify(await res.json(), null, 2);
      };
      document.getElementById("me-btn").addEventListener("click", checkSession);
      checkSession();
    </script>
  </body>
</html>`);
});

app.get("/auth/login", async (c) => {
  const config = await fetchDiscovery();
  const state = randomBytes(32).toString("base64url");
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  setCookie(c, "oidc_state", state, { httpOnly: true, sameSite: "Lax", path: "/" });
  setCookie(c, "oidc_cv", codeVerifier, { httpOnly: true, sameSite: "Lax", path: "/" });

  const authUrl = new URL(config.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid profile email");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return c.redirect(authUrl.toString());
});

app.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const savedState = getCookie(c, "oidc_state");
  const codeVerifier = getCookie(c, "oidc_cv");

  deleteCookie(c, "oidc_state", { path: "/" });
  deleteCookie(c, "oidc_cv", { path: "/" });

  if (!code || !state || state !== savedState || !codeVerifier) {
    return c.json({ error: "invalid state or missing code_verifier" }, 400);
  }

  const config = await fetchDiscovery();
  const tokenRes = await fetch(config.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenRes.ok) {
    return c.json({ error: "token exchange failed", detail: await tokenRes.text() }, 400);
  }

  const tokenData = (await tokenRes.json()) as { id_token: string };
  const payloadBase64 = tokenData.id_token.split(".")[1];
  // In production, verify signature with JWKS and validate claims (iss, aud, exp)
  const claims = JSON.parse(
    Buffer.from(payloadBase64, "base64url").toString("utf8"),
  ) as IdTokenClaims;

  const sessionId = randomBytes(32).toString("base64url");
  sessions.set(sessionId, { idToken: tokenData.id_token, claims });
  setCookie(c, "session_id", sessionId, { httpOnly: true, sameSite: "Lax", path: "/" });

  return c.redirect("/");
});

app.get("/me", (c) => {
  const sessionId = getCookie(c, "session_id");
  const session = sessionId ? sessions.get(sessionId) : undefined;
  if (!session) {
    return c.json({ loggedIn: false }, 401);
  }

  return c.json({
    loggedIn: true,
    user: {
      sub: session.claims.sub,
      username: session.claims.preferred_username,
      email: session.claims.email,
    },
    claims: session.claims,
  });
});

app.get("/auth/logout", async (c) => {
  const sessionId = getCookie(c, "session_id");
  const session = sessionId ? sessions.get(sessionId) : undefined;
  if (sessionId) {
    sessions.delete(sessionId);
  }
  deleteCookie(c, "session_id", { path: "/" });

  if (!session) {
    return c.redirect("/");
  }

  const config = await fetchDiscovery();
  const logoutUrl = new URL(config.end_session_endpoint);
  logoutUrl.searchParams.set("id_token_hint", session.idToken);
  logoutUrl.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);

  return c.redirect(logoutUrl.toString());
});

const port = Number(process.env.PORT ?? 3000);

serve({
  fetch: app.fetch,
  port,
});

console.log(`Server is running on http://localhost:${port}`);
