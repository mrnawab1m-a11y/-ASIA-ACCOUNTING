const crypto = require("node:crypto");
const { neon } = require("@neondatabase/serverless");
const COOKIE = "asia_admin_session";

function send(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
}
function cookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) {
      const key = part.slice(0, i).trim();
      try { out[key] = decodeURIComponent(part.slice(i + 1).trim()); } catch {}
    }
  }
  return out;
}
async function bodyOf(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 12000) throw new Error("body_too_large");
  }
  try { return JSON.parse(raw || "{}"); } catch { return {}; }
}
const clean = value => String(value ?? "").trim();

module.exports = async function handler(req, res) {
  if (!["GET", "POST"].includes(req.method)) return send(res, 405, { ok: false, error: "method_not_allowed" });
  if (!process.env.DATABASE_URL) return send(res, 503, { ok: false, error: "database_not_configured" });

  const token = cookies(req.headers.cookie || "")[COOKIE];
  if (!token || !/^[a-f0-9]{64}$/i.test(token)) return send(res, 401, { ok: false, error: "unauthorized" });
  if (req.method === "POST") {
    const origin = req.headers.origin;
    const host = req.headers.host;
    try {
      if (!origin || !host || new URL(origin).host !== host) return send(res, 403, { ok: false, error: "origin_not_allowed" });
    } catch { return send(res, 403, { ok: false, error: "origin_not_allowed" }); }
  }

  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const sql = neon(process.env.DATABASE_URL);
  try {
    const sessions = await sql`SELECT u.workspace_id
      FROM auth_sessions s JOIN app_users u ON u.id = s.user_id
      WHERE s.token_hash = ${tokenHash} AND s.revoked_at IS NULL
        AND s.expires_at > now() AND u.active = true AND u.is_admin = true
      LIMIT 1`;
    if (!sessions.length) return send(res, 401, { ok: false, error: "unauthorized" });
    const workspaceId = sessions[0].workspace_id;

    if (req.method === "GET") {
      const rows = await sql`SELECT p.id, p.name, p.category, p.brand, p.model, p.size, p.unit, p.created_at,
        COALESCE(SUM(sm.quantity_delta), 0)::text AS stock_quantity
        FROM products p
        LEFT JOIN stock_movements sm ON sm.product_id = p.id AND sm.workspace_id = p.workspace_id
        WHERE p.workspace_id = ${workspaceId} AND p.active = true
        GROUP BY p.id ORDER BY p.created_at DESC LIMIT 200`;
      return send(res, 200, { ok: true, products: rows });
    }

    let input;
    try { input = await bodyOf(req); }
    catch { return send(res, 413, { ok: false, error: "request_too_large" }); }
    const name = clean(input.name), unit = clean(input.unit);
    const category = clean(input.category), brand = clean(input.brand);
    const model = clean(input.model), size = clean(input.size);
    if (!name || name.length > 120) return send(res, 400, { ok: false, error: "invalid_name" });
    if (!unit || unit.length > 40) return send(res, 400, { ok: false, error: "invalid_unit" });
    if ([category, brand, model, size].some(v => v.length > 120)) return send(res, 400, { ok: false, error: "field_too_long" });

    const rows = await sql`INSERT INTO products (workspace_id, name, category, brand, model, size, unit)
      VALUES (${workspaceId}, ${name}, ${category || null}, ${brand || null}, ${model || null}, ${size || null}, ${unit})
      RETURNING id, name, category, brand, model, size, unit, created_at`;
    return send(res, 201, { ok: true, product: { ...rows[0], stock_quantity: "0" } });
  } catch (error) {
    console.error("Asia products API error:", error?.message || "unknown");
    return send(res, 500, { ok: false, error: "server_error" });
  }
};
