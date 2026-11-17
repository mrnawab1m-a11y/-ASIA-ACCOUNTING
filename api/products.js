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
      const rows = await sql`SELECT p.id, p.name, p.category, p.brand, p.model, p.size, p.unit, p.sale_price, p.created_at,
        COALESCE(SUM(sm.quantity_delta), 0)::text AS stock_quantity,
        COALESCE(MAX(cost.stock_value), 0)::text AS stock_value,
        CASE WHEN COALESCE(SUM(sm.quantity_delta), 0) > 0
          THEN (COALESCE(MAX(cost.stock_value), 0) / SUM(sm.quantity_delta))::text ELSE '0' END AS stock_unit_cost
        FROM products p
        LEFT JOIN stock_movements sm ON sm.product_id = p.id AND sm.workspace_id = p.workspace_id
        LEFT JOIN LATERAL (
          SELECT SUM(scl.quantity_remaining * scl.unit_cost) AS stock_value
          FROM stock_cost_layers scl
          WHERE scl.product_id = p.id AND scl.workspace_id = p.workspace_id
        ) cost ON true
        WHERE p.workspace_id = ${workspaceId} AND p.active = true
        GROUP BY p.id ORDER BY p.created_at DESC`;
      return send(res, 200, { ok: true, products: rows });
    }

    let input;
    try { input = await bodyOf(req); }
    catch { return send(res, 413, { ok: false, error: "request_too_large" }); }
    const name = clean(input.name), unit = clean(input.unit);
    const category = clean(input.category), brand = clean(input.brand);
    const model = clean(input.model), size = clean(input.size);
    const salePrice = input.sale_price === undefined || input.sale_price === '' ? null : Number(input.sale_price);
    if (salePrice !== null && (!Number.isFinite(salePrice) || salePrice < 0 || salePrice > 1000000000)) return send(res, 400, { ok: false, error: 'invalid_sale_price' });
    if (!name || name.length > 120) return send(res, 400, { ok: false, error: "invalid_name" });
    if (!unit || unit.length > 40) return send(res, 400, { ok: false, error: "invalid_unit" });
    if ([category, brand, model, size].some(v => v.length > 120)) return send(res, 400, { ok: false, error: "field_too_long" });

    const initialQuantity = Number(input.initial_stock_quantity ?? 0);
    const initialUnitCost = Number(input.initial_unit_cost ?? 0);
    if (!Number.isFinite(initialQuantity) || initialQuantity < 0 || initialQuantity > 1000000000 ||
        !Number.isFinite(initialUnitCost) || initialUnitCost < 0 || initialUnitCost > 1000000000) {
      return send(res, 400, { ok: false, error: "invalid_opening_stock" });
    }
    if (initialQuantity > 0 && initialUnitCost <= 0) {
      return send(res, 400, { ok: false, error: "opening_cost_required" });
    }

    const productId = crypto.randomUUID();
    const statements = [sql`INSERT INTO products (id, workspace_id, name, category, brand, model, size, unit, sale_price)
      VALUES (${productId}, ${workspaceId}, ${name}, ${category || null}, ${brand || null}, ${model || null}, ${size || null}, ${unit}, ${salePrice})`];
    let openingPurchaseId = null;
    let openingTotal = 0;
    if (initialQuantity > 0) {
      openingPurchaseId = crypto.randomUUID();
      const documentNo = "OPEN-" + Date.now().toString(36).toUpperCase() + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
      openingTotal = Math.round(initialQuantity * initialUnitCost * 100) / 100;
      statements.push(sql`INSERT INTO purchases (id, workspace_id, supplier_id, document_no, currency, exchange_rate, total_amount, paid_amount, notes)
        VALUES (${openingPurchaseId}, ${workspaceId}, NULL, ${documentNo}, 'AFN', 1, ${openingTotal}, 0, 'موجودی ابتدایی هنگام تعریف محصول')`);
      statements.push(sql`INSERT INTO purchase_items (purchase_id, product_id, quantity, unit, unit_cost, currency, line_total)
        VALUES (${openingPurchaseId}, ${productId}, ${initialQuantity}, ${unit}, ${initialUnitCost}, 'AFN', ${openingTotal})`);
      statements.push(sql`INSERT INTO stock_movements (workspace_id, product_id, movement_type, quantity_delta, unit, unit_cost, source_id, notes)
        VALUES (${workspaceId}, ${productId}, 'purchase', ${initialQuantity}, ${unit}, ${initialUnitCost}, ${openingPurchaseId}, 'ثبت موجودی ابتدایی')`);
      statements.push(sql`INSERT INTO stock_cost_layers (workspace_id, product_id, source_purchase_id, quantity_received, quantity_remaining, unit_cost)
        VALUES (${workspaceId}, ${productId}, ${openingPurchaseId}, ${initialQuantity}, ${initialQuantity}, ${initialUnitCost})`);
    }
    await sql.transaction(statements);
    const rows = await sql`SELECT id, name, category, brand, model, size, unit, sale_price, created_at FROM products WHERE id = ${productId} AND workspace_id = ${workspaceId}`;
    return send(res, 201, { ok: true, product: { ...rows[0], stock_quantity: String(initialQuantity), opening_stock_value: openingTotal } });
  } catch (error) {
    console.error("Asia products API error:", error?.message || "unknown");
    return send(res, 500, { ok: false, error: "server_error" });
  }
};
