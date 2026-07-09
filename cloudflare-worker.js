import { AwsClient } from "aws4fetch";

// Environment bindings (set via `wrangler secret put` / wrangler.toml [vars]):
//   SIGNING_SECRET     - shared HMAC secret with your backend, secret
//   HETZNER_ACCESS_KEY - S3 access key, secret
//   HETZNER_SECRET_KEY - S3 secret key, secret
//   HETZNER_ENDPOINT   - e.g. "fsn1.your-objectstorage.com", var
//   HETZNER_BUCKET     - bucket name, var
//   ALLOWED_ORIGIN     - e.g. "https://shop.example.com", var
//   CACHE_TTL_SECONDS  - e.g. "86400", var

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", { status: 405 });
    }

    const url = new URL(request.url);
    const key = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    const exp = url.searchParams.get("exp");
    const sig = url.searchParams.get("sig");

    if (!key || !exp || !sig) {
      return new Response("Missing token", { status: 401 });
    }

    // 1. Reject expired tokens outright.
    const expiresAt = Number(exp);
    if (!Number.isFinite(expiresAt) || Date.now() / 1000 > expiresAt) {
      return new Response("Link expired", { status: 403 });
    }

    // 2. Verify the HMAC signature covers this exact key + expiry.
    const valid = await verifySignature(key, exp, sig, env.SIGNING_SECRET);
    if (!valid) {
      return new Response("Invalid signature", { status: 403 });
    }

    // 3. Soft origin check - defense in depth, not the primary control.
    // Exact match only: startsWith() would let "https://store.com.evil.com"
    // through, since that string does start with "https://store.com".
    const allowedOrigins = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
    const origin = request.headers.get("Origin") || "";
    const allowOrigin = allowedOrigins.includes(origin) ? origin : "";
    if (allowedOrigins.length && origin && !allowOrigin) {
      return new Response("Forbidden origin", { status: 403 });
    }

    // 4. Cache key deliberately excludes exp/sig, so every valid caller
    //    for the same object shares one edge cache entry instead of
    //    fragmenting the cache per-token.
    const cacheKeyUrl = new URL(request.url);
    cacheKeyUrl.search = "";
    const cacheKey = new Request(cacheKeyUrl.toString(), { method: "GET" });
    const cache = caches.default;

    let response = await cache.match(cacheKey);
    if (response) {
      return withCorsHeaders(response, allowOrigin);
    }

    // 5. Cache miss - sign and fetch the real object from Hetzner.
    const client = new AwsClient({
      accessKeyId: env.HETZNER_ACCESS_KEY,
      secretAccessKey: env.HETZNER_SECRET_KEY,
      service: "s3",
      region: "auto",
    });

    const originUrl = `https://${env.HETZNER_BUCKET}.${env.HETZNER_ENDPOINT}/${key}`;
    const signedRequest = await client.sign(originUrl, { method: "GET" });
    const originResponse = await fetch(signedRequest);

    if (!originResponse.ok) {
      return new Response("Asset not found", { status: originResponse.status });
    }

    response = new Response(originResponse.body, originResponse);
    response.headers.set("Cache-Control", `public, max-age=${env.CACHE_TTL_SECONDS || 86400}`);
    response.headers.delete("Set-Cookie");

    ctx.waitUntil(cache.put(cacheKey, response.clone()));

    return withCorsHeaders(response, allowOrigin);
  },
};

function withCorsHeaders(response, allowOrigin) {
  const out = new Response(response.body, response);
  out.headers.set("Access-Control-Allow-Origin", allowOrigin);
  out.headers.set("Vary", "Origin");
  return out;
}

async function verifySignature(key, exp, sig, secret) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(`${key}:${exp}`));
  const expectedHex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return timingSafeEqual(expectedHex, sig);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}