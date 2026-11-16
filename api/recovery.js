const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { neon } = require("@neondatabase/serverless");
const scrypt = promisify(crypto.scrypt);

const send = (res, status, data) => {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
};

async function body(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let raw = "";
  for await (const chunk of req) raw += chunk;
  try { return JSON.parse(raw || "{}"); } catch { return {}; }
}

async function hash(value) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(value, salt, 64);
  return salt.toString("hex") + "$" + key.toString("hex");
}

async function verify(value, stored) {
  const [saltHex, keyHex, ...extra] = String(stored || "").split("$");
  if (extra.length || !/^[a-f0-9]{32}$/i.test(saltHex || "") || !/^[a-f0-9]{128}$/i.test(keyHex || "")) return false;
  const actual = await scrypt(value, Buffer.from(saltHex, "hex"), 64);
  const expected = Buffer.from(keyHex, "hex");
  return crypto.timingSafeEqual(actual, expected);
}

const normalizeCode = value => String(value || "").replace(/[^a-f0-9]/gi, "").toLowerCase();
const newCode = () => crypto.randomBytes(16).toString("hex").toUpperCase().match(/.{1,4}/g).join("-");
const safeEqual = (a, b) => {
  if (!a || !b) return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = async (req, res) => {
  if (req.method !== "POST") return send(res, 405, { ok: false, error: "method_not_allowed" });
  if (!process.env.DATABASE_URL) return send(res, 503, { ok: false, error: "database_not_configured" });

  const input = await body(req);
  const pin = String(input.pin || "");
  if (!/^[0-9]{6}$/.test(pin)) return send(res, 400, { ok: false, error: "pin_must_be_six_digits" });

  const sql = neon(process.env.DATABASE_URL);

  try {
    const users = await sql`SELECT id, username, recovery_code_hash FROM app_users WHERE active = true AND is_admin = true ORDER BY created_at ASC LIMIT 1`;
    if (!users.length) return send(res, 404, { ok: false, error: "admin_not_found" });

    const user = users[0];

    if (input.action === "setup") {
      if (!safeEqual(String(input.setupToken || ""), process.env.ASIA_SETUP_TOKEN)) {
        return send(res, 403, { ok: false, error: "setup_link_invalid" });
      }
      if (user.recovery_code_hash) return send(res, 409, { ok: false, error: "setup_already_completed" });
    } else if (input.action === "recover") {
      const recoveryCode = normalizeCode(input.recoveryCode);
      if (!/^[a-f0-9]{32}$/.test(recoveryCode) || !user.recovery_code_hash || !(await verify(recoveryCode, user.recovery_code_hash))) {
        return send(res, 401, { ok: false, error: "recovery_code_invalid" });
      }
    } else {
      return send(res, 400, { ok: false, error: "unknown_action" });
    }

    const pinHash = await hash(pin);
    const recoveryCode = newCode();
    const recoveryHash = await hash(normalizeCode(recoveryCode));
    let updated;

    if (input.action === "setup") {
      updated = await sql`UPDATE app_users SET pin_hash = ${pinHash}, recovery_code_hash = ${recoveryHash}, recovery_code_used_at = NULL WHERE id = ${user.id} AND recovery_code_hash IS NULL RETURNING id`;
    } else {
      updated = await sql`UPDATE app_users SET pin_hash = ${pinHash}, recovery_code_hash = ${recoveryHash}, recovery_code_used_at = now() WHERE id = ${user.id} AND recovery_code_hash = ${user.recovery_code_hash} RETURNING id`;
    }

    if (!updated.length) return send(res, 409, { ok: false, error: "code_already_used_or_setup_done" });

    await sql`UPDATE auth_sessions SET revoked_at = now() WHERE user_id = ${user.id} AND revoked_at IS NULL`;
    await sql`DELETE FROM auth_attempts`;

    return send(res, 200, { ok: true, username: user.username, recoveryCode });
  } catch (error) {
    console.error("Asia recovery error", error?.message || "unknown");
    return send(res, 500, { ok: false, error: "server_error" });
  }
};
