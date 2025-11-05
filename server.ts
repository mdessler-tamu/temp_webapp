import "dotenv/config";
import express from "express";
import session from "express-session";
import cors from "cors";
import helmet from "helmet";
import { Issuer, generators, Client } from "openid-client";
import connectRedis from "connect-redis";
import { Redis } from "ioredis";

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  BASE_URL,            // e.g., https://your-service.onrender.com
  SESSION_SECRET,
  REDIS_URL,           // e.g., rediss://:password@host:port
  CORS_ORIGIN,         // e.g., https://your-frontend.com or same as BASE_URL
  NODE_ENV
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !BASE_URL || !SESSION_SECRET) {
  throw new Error("Missing required env vars");
}

async function main() {
  // 1) Discover Google OIDC metadata
  const googleIssuer = await Issuer.discover("https://accounts.google.com");

  // 2) Create OIDC client
  const client: Client = new googleIssuer.Client({
    client_id: GOOGLE_CLIENT_ID,
    client_secret: GOOGLE_CLIENT_SECRET,
    redirect_uris: [`${BASE_URL}/auth/callback`],
    response_types: ["code"],
  });

  const app = express();

  // Security hardening
  app.use(helmet({ contentSecurityPolicy: false })); // keep CSP off unless you configure it

  // Trust Render's proxy for secure cookies + correct protocol
  app.set("trust proxy", 1);

  // CORS (adjust for your deployment)
  // Same-origin (frontend served by this server): you can skip CORS.
  // Cross-origin SPA: set CORS_ORIGIN to your frontend origin and enable credentials.
  if (CORS_ORIGIN) {
    app.use(
      cors({
        origin: CORS_ORIGIN.split(",").map(s => s.trim()),
        credentials: true,
      })
    );
  }

  // Persistent sessions using Redis (recommended on Render)
  const RedisStore = connectRedis(session);
  const store = REDIS_URL
    ? new Redis(REDIS_URL, { tls: REDIS_URL.startsWith("rediss://") ? {} : undefined })
    : null;

  app.use(
    session({
      store: store ? new RedisStore({ client: store as unknown as Redis }) : undefined,
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: true,                // Render is HTTPS
        sameSite: CORS_ORIGIN ? "none" : "lax", // cross-site needs "none"
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      },
    })
  );

  // Health check for Render
  app.get("/healthz", (_req, res) => res.status(200).send("ok"));

  // 3) Start login
  app.get("/auth/login", (req, res) => {
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const state = generators.state();
    const nonce = generators.nonce();

    (req.session as any).codeVerifier = codeVerifier;
    (req.session as any).state = state;
    (req.session as any).nonce = nonce;

    const authUrl = client.authorizationUrl({
      scope: "openid email profile",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce,
      // first login can request refresh tokens:
      // access_type: "offline",
      // prompt: "consent",
    });

    res.redirect(authUrl);
  });

  // 4) OAuth callback
  app.get("/auth/callback", async (req, res, next) => {
    try {
      const params = client.callbackParams(req);
      const codeVerifier = (req.session as any).codeVerifier;
      const expectedState = (req.session as any).state;
      const expectedNonce = (req.session as any).nonce;

      const tokenSet = await client.callback(
        `${BASE_URL}/auth/callback`,
        params,
        { code_verifier: codeVerifier, state: expectedState, nonce: expectedNonce }
      );

      const claims = tokenSet.claims();

      (req.session as any).user = {
        sub: claims.sub,
        email: claims.email,
        name: claims.name,
        picture: claims.picture,
      };

      // If you requested refresh tokens above:
      // (req.session as any).refresh_token = tokenSet.refresh_token;

      res.redirect("/profile");
    } catch (err) {
      next(err);
    }
  });

  // 5) Protected endpoint
  app.get("/profile", (req, res) => {
    const user = (req.session as any).user;
    if (!user) return res.status(401).send("Not logged in. Visit /auth/login");
    res.type("html").send(`
      <h1>Profile</h1>
      ${user.picture ? `<img src="${user.picture}" alt="avatar" width="64" height="64"/>` : ""}
      <pre>${JSON.stringify(user, null, 2)}</pre>
      <a href="/auth/logout">Logout</a>
    `);
  });

  // 6) Logout (local)
  app.get("/auth/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
  });

  // 7) Home
  app.get("/", (_req, res) => {
    res.type("html").send(`<a href="/auth/login">Sign in with Google</a>`);
  });

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  app.listen(port, () => {
    console.log(`Listening on ${port}. BASE_URL=${BASE_URL}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
