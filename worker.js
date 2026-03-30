/**
 * Cloudflare Workers — Hybrid Proxy
 *
 * Forwarded to https://proxy.wavembed.lol (with M3U8 URL rewriting):
 *   GET /m3u8-proxy
 *   GET /ts-proxy
 *   GET /mp4-proxy
 *   GET /subtitle
 *
 * Handled locally by the worker:
 *   GET /         — version info
 *   GET /health   — worker health check
 *   GET /fetch    — direct fetch proxy (streams response back to client)
 */

const UPSTREAM_HOST = "proxy3.wavembed.lol";
const UPSTREAM_BASE = `https://${UPSTREAM_HOST}`;

const VERSION = "1.0.1";

const FORWARDED_PATHS = new Set([
  "/m3u8-proxy",
  "/ts-proxy",
  "/mp4-proxy",
  "/subtitle",
]);

const BLOCKED_REQUEST_HEADERS = new Set([
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "x-forwarded-proto",
  "x-real-ip",
  "host",
]);

const BLOCKED_RESPONSE_HEADERS = new Set([
  "content-encoding",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "trailer",
  "proxy-authenticate",
  "proxy-authorization",
]);

// Content-types that indicate an M3U8 playlist response that needs rewriting
const M3U8_CONTENT_TYPES = new Set([
  "application/vnd.apple.mpegurl",
  "application/x-mpegurl",
  "audio/mpegurl",
  "audio/x-mpegurl",
  "text/plain", // some CDNs serve playlists as text/plain
]);

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Expose-Headers":
      "Content-Length, Content-Range, Content-Type, Date, Server, X-Cache-Hit, X-Upstream-Status",
    "Access-Control-Max-Age": "86400",
    "Timing-Allow-Origin": "*",
  };
}

// ---------------------------------------------------------------------------
// URL validation (SSRF protection)
// ---------------------------------------------------------------------------

function validateUrl(urlString) {
  try {
    const url = new URL(urlString);
    if (!["http:", "https:"].includes(url.protocol)) {
      return { valid: false, error: "Only HTTP/HTTPS protocols allowed" };
    }
    const h = url.hostname.toLowerCase();
    if (
      h === "localhost" ||
      h === "[::1]" ||
      /^127\./.test(h) ||
      /^10\./.test(h) ||
      /^192\.168\./.test(h) ||
      /^169\.254\./.test(h) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    ) {
      return { valid: false, error: "Private/reserved IPs not allowed" };
    }
    return { valid: true };
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }
}

// ---------------------------------------------------------------------------
// Custom headers parser
// Supports: ?headers={"X-Foo":"bar"} | base64 JSON | ?header_x_foo=bar
// ---------------------------------------------------------------------------

function parseCustomHeaders(searchParams) {
  const customHeaders = {};
  const headersParam = searchParams.get("headers");
  if (headersParam) {
    try {
      let obj;
      try {
        obj = JSON.parse(headersParam);
      } catch {
        obj = JSON.parse(atob(headersParam));
      }
      Object.assign(customHeaders, obj);
    } catch {
      /* ignore malformed */
    }
  }
  for (const [key, value] of searchParams.entries()) {
    if (key.startsWith("header_")) {
      customHeaders[key.slice(7).replace(/_/g, "-")] = value;
    }
  }
  return customHeaders;
}

// ---------------------------------------------------------------------------
// Anti-bot: rotating User-Agents
// ---------------------------------------------------------------------------

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
];

const ACCEPT_LANGUAGES = [
  "en-US,en;q=0.9",
  "en-US,en;q=0.9,es;q=0.8",
  "en-GB,en;q=0.9",
  "en-US,en;q=0.8",
];

const SEC_CH_UA_MAP = {
  124: '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  123: '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
};

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function buildRequestHeaders(customHeaders = {}, includeReferer = true) {
  const ua =
    customHeaders["User-Agent"] ||
    customHeaders["user-agent"] ||
    pickRandom(USER_AGENTS);
  const chromeVerMatch = ua.match(/Chrome\/(\d+)/);
  const chromeVer = chromeVerMatch ? chromeVerMatch[1] : null;
  const secCHUA =
    (chromeVer && SEC_CH_UA_MAP[chromeVer]) ||
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"';

  const headers = {
    "User-Agent": ua,
    Accept: "*/*",
    "Accept-Language": pickRandom(ACCEPT_LANGUAGES),
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache",
    Pragma: "no-cache",
    Connection: "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "cross-site",
    "sec-ch-ua": secCHUA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": ua.includes("Macintosh")
      ? '"macOS"'
      : ua.includes("Linux")
        ? '"Linux"'
        : '"Windows"',
  };

  for (const [key, value] of Object.entries(customHeaders)) {
    if (key.toLowerCase() === "referer" && !includeReferer) continue;
    headers[key] = value;
  }

  return headers;
}

// ---------------------------------------------------------------------------
// M3U8 URL rewriter
// Replaces every occurrence of the upstream host with the worker's own host
// so all proxied segment/playlist URLs route through the worker, not the
// backend directly.
// ---------------------------------------------------------------------------

function rewriteM3U8Urls(text, workerBase) {
  // Replace both http and https variants of the upstream host
  const httpUpstream = `http://${UPSTREAM_HOST}`;
  const httpsUpstream = `https://${UPSTREAM_HOST}`;

  return text
    .replaceAll(httpsUpstream, workerBase)
    .replaceAll(httpUpstream, workerBase);
}

// Returns true if the response looks like an M3U8 playlist that needs rewriting
function isM3U8Response(response) {
  const ct = (response.headers.get("content-type") || "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (M3U8_CONTENT_TYPES.has(ct)) return true;
  // Also catch playlists served with wrong/missing content-type by peeking at the URL path
  return false;
}

// ---------------------------------------------------------------------------
// /fetch handler — runs entirely in the worker
// ---------------------------------------------------------------------------

async function handleFetch(request) {
  const url = new URL(request.url);
  const targetUrl = url.searchParams.get("url");

  if (!targetUrl) {
    return new Response(JSON.stringify({ error: "Missing url parameter" }), {
      status: 400,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
  }

  const { valid, error } = validateUrl(targetUrl);
  if (!valid) {
    return new Response(JSON.stringify({ error }), {
      status: 400,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
  }

  const customHeaders = parseCustomHeaders(url.searchParams);
  const requestHeaders = buildRequestHeaders(customHeaders, true);

  const rangeHeader = request.headers.get("Range");
  if (rangeHeader) requestHeaders["Range"] = rangeHeader;

  const hostOverride = (url.searchParams.get("host") || "").trim();
  if (hostOverride) requestHeaders["Host"] = hostOverride;

  let upstreamResponse;
  try {
    upstreamResponse = await fetch(targetUrl, {
      method: request.method,
      headers: requestHeaders,
      redirect: "follow",
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Bad Gateway", message: err.message }),
      {
        status: 502,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      },
    );
  }

  if (!upstreamResponse.ok && upstreamResponse.status !== 206) {
    return new Response(
      JSON.stringify({
        error: "Failed to fetch resource",
        status: upstreamResponse.status,
      }),
      {
        status: upstreamResponse.status,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      },
    );
  }

  const responseHeaders = new Headers();
  for (const [key, value] of upstreamResponse.headers.entries()) {
    if (!BLOCKED_RESPONSE_HEADERS.has(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  }
  responseHeaders.set("Accept-Ranges", "bytes");
  responseHeaders.set("X-Upstream-Status", String(upstreamResponse.status));
  responseHeaders.set(
    "Cache-Control",
    "public, max-age=60, stale-while-revalidate=30",
  );
  for (const [key, value] of Object.entries(corsHeaders())) {
    responseHeaders.set(key, value);
  }

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  });
}

// ---------------------------------------------------------------------------
// Forward handler — sends request to proxy.wavembed.lol
// For /m3u8-proxy responses, rewrites all upstream host references in the
// returned playlist so every URL routes through the worker instead.
// ---------------------------------------------------------------------------

async function handleForward(request, isM3U8Route, event) {
  const cache = caches.default;
  // include full URL (path + query)
  const cacheKey = new Request(request.url, request);
  let cached = await cache.match(cacheKey);
  if (cached) {
    const headers = new Headers(cached.headers);
    headers.set("X-Cache-Hit", "true");

    return new Response(cached.body, {
      status: cached.status,
      headers,
    });
  }
  const url = new URL(request.url);
  const upstreamUrl = new URL(url.pathname + url.search, UPSTREAM_BASE);

  const outboundHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    if (!BLOCKED_REQUEST_HEADERS.has(key.toLowerCase())) {
      outboundHeaders.set(key, value);
    }
  }
  outboundHeaders.set("Host", UPSTREAM_HOST);

  let upstreamResponse;
  try {
    upstreamResponse = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers: outboundHeaders,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "follow",
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Bad Gateway", message: err.message }),
      {
        status: 502,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      },
    );
  }

  const responseHeaders = new Headers();
  for (const [key, value] of upstreamResponse.headers.entries()) {
    if (!BLOCKED_RESPONSE_HEADERS.has(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  }
  for (const [key, value] of Object.entries(corsHeaders())) {
    responseHeaders.set(key, value);
  }

  // ---- Edge Cache TTL ----
  let ttl = 300;

  if (url.pathname === "/m3u8-proxy") ttl = 60;
  if (url.pathname === "/ts-proxy") ttl = 3600;
  if (url.pathname === "/mp4-proxy") ttl = 86400;
  if (url.pathname === "/subtitle") ttl = 86400;

  responseHeaders.set(
    "Cache-Control",
    `public, s-maxage=${ttl}, stale-while-revalidate=120`,
  );

  // ── M3U8 rewrite ──────────────────────────────────────────────────────────
  // If this is a playlist route AND the response looks like a playlist,
  // buffer the text and replace all upstream host references with the
  // worker's own origin so segment/sub-playlist URLs route through us.
  if (isM3U8Route && isM3U8Response(upstreamResponse)) {
    const workerBase = `${url.protocol}//${url.host}`;
    const text = await upstreamResponse.text();
    const rewritten = rewriteM3U8Urls(text, workerBase);

    // Remove content-length — byte count changed after rewrite
    responseHeaders.delete("content-length");

    const response = new Response(rewritten, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });

    if (upstreamResponse.ok || upstreamResponse.status === 206) {
      event.waitUntil(cache.put(cacheKey, response.clone()));
    }

    return response;
  }

  // All other routes: stream body straight through
  const response = new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  });

  // Cache only successful responses — clone BEFORE returning so the stream
  // isn't consumed. The per-route Cache-Control is already set above; do NOT
  // overwrite it here.
  if (upstreamResponse.ok || upstreamResponse.status === 206) {
    event.waitUntil(cache.put(cacheKey, response.clone()));
  }

  return response;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, event) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 200, headers: corsHeaders() });
    }

    if (url.pathname === "/") {
      return new Response(
        JSON.stringify({
          name: "Shouldn't be here....",
          version: VERSION,
          //upstream: UPSTREAM_HOST,
          //routes: ["/", "/health", "/fetch", "/m3u8-proxy", "/ts-proxy", "/mp4-proxy", "/subtitle"],
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        },
      );
    }

    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          status: "ok",
          worker: true,
          upstream: UPSTREAM_HOST,
          timestamp: new Date().toISOString(),
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        },
      );
    }

    if (url.pathname === "/fetch") {
      return handleFetch(request);
    }

    if (FORWARDED_PATHS.has(url.pathname)) {
      const isM3U8Route = url.pathname === "/m3u8-proxy";
      return handleForward(request, isM3U8Route, event);
    }

    return new Response(
      JSON.stringify({ error: "Not Found", path: url.pathname }),
      {
        status: 404,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      },
    );
  },
};
