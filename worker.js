/**
 * Cloudflare Worker — Cookie SameSite Checker backend
 *
 * Deploy:
 *   1. Dashboard: workers.cloudflare.com → Create Worker → paste this file
 *   2. CLI:  npx wrangler deploy worker.js --name cookie-checker
 *
 * After deploy, paste your *.workers.dev URL into the frontend "⚙ API" field.
 */

const UA = "Mozilla/5.0 (Pentest Evidence Collector; Cookie SameSite Checker)";
const SUSPICIOUS = ["session", "auth", "token", "sid", "sess", "jwt", "login"];

function parseCookieHeader(raw) {
  const parts = raw.split(";").map(p => p.trim());
  const eq = parts[0].indexOf("=");
  if (eq === -1) return null;

  const name = parts[0].slice(0, eq).trim();
  const attrs = { samesite: null, secure: false, httponly: false, domain: "", path: "/" };

  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower === "secure") { attrs.secure = true; continue; }
    if (lower === "httponly") { attrs.httponly = true; continue; }
    if (lower.startsWith("samesite=")) {
      const v = part.slice(9).trim();
      attrs.samesite = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
    } else if (lower.startsWith("domain=")) {
      attrs.domain = part.slice(7).trim();
    } else if (lower.startsWith("path=")) {
      attrs.path = part.slice(5).trim();
    }
  }

  return { name, ...attrs };
}

function classifyRisk(cookie) {
  const { samesite, secure, httponly, name } = cookie;
  const sensitive = SUSPICIOUS.some(t => name.toLowerCase().includes(t));

  if (!samesite)                         return ["ALTO",        "Sin SameSite"];
  if (samesite === "None" && !secure)    return ["ALTO",        "SameSite=None sin Secure"];
  if (samesite === "None" && secure) {
    if (sensitive && !httponly)          return ["ALTO",        "SameSite=None y sin HttpOnly en cookie sensible"];
                                         return ["MEDIO",       "SameSite=None con Secure"];
  }
  if (samesite === "Lax" || samesite === "Strict") {
    if (sensitive && !httponly)          return ["MEDIO",       "Cookie sensible sin HttpOnly"];
                                         return ["INFORMATIVO", `SameSite=${samesite}`];
  }
                                         return ["INFORMATIVO", `SameSite=${samesite}`];
}

async function checkDomain(domain) {
  let lastError = null;
  for (const url of [`https://${domain}`, `http://${domain}`]) {
    try {
      const resp = await fetch(url, {
        redirect: "follow",
        headers: { "User-Agent": UA },
      });

      // getAll() is a CF Workers extension for Set-Cookie
      const setCookies = resp.headers.getAll("set-cookie");
      const cookies = [];

      for (const sc of setCookies) {
        const c = parseCookieHeader(sc);
        if (!c) continue;
        const [risk, issue] = classifyRisk(c);
        cookies.push({ ...c, risk, issue });
      }

      return { domain, cookies, error: null };
    } catch (e) {
      lastError = e;
    }
  }
  return { domain, cookies: [], error: lastError?.message ?? "Error desconocido" };
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/check") {
      return new Response("Not found", { status: 404 });
    }

    const raw = url.searchParams.get("domains") || "";
    const domains = [...new Set(raw.split(",").map(d => d.trim().toLowerCase()).filter(Boolean))];

    if (!domains.length) {
      return new Response(JSON.stringify({ error: "No domains provided" }), {
        status: 400,
        headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      });
    }

    const results = await Promise.all(domains.map(checkDomain));

    return new Response(JSON.stringify(results), {
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    });
  },
};
