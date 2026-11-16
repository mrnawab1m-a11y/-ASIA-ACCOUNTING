const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { neon } = require("@neondatabase/serverless");
const scrypt = promisify(crypto.scrypt);
const COOKIE = "asia_admin_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;

function reply(res, status, data, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [k,v] of Object.entries(headers)) res.setHeader(k,v);
  res.end(JSON.stringify(data));
}
function parseCookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) {
      const key = part.slice(0,i).trim();
      try { out[key] = decodeURIComponent(part.slice(i+1).trim()); } catch {}
    }
  }
  return out;
}
function setCookie(token, age) {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
}
function ipDigest(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = (typeof forwarded === "string" ? forwarded.split(",")[0].trim() : "") || req.socket?.remoteAddress || "unknown";
  return crypto.createHash("sha256").update(ip).digest("hex");
}
async function bodyOf(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let data = "";
  for await (const chunk of req) data += chunk;
  try { return JSON.parse(data || "{}"); } catch { return {}; }
}
async function verifyPin(pin, stored) {
  const [saltHex, keyHex, extra] = String(stored || "").split("$");
  if (extra !== undefined || !/^[a-f0-9]{32}$/i.test(saltHex || "") || !/^[a-f0-9]{128}$/i.test(keyHex || "")) return false;
  const actual = await scrypt(pin, Buffer.from(saltHex,"hex"), 64);
  const expected = Buffer.from(keyHex,"hex");
  return crypto.timingSafeEqual(actual, expected);
}
module.exports = async function handler(req,res) {
  if (!process.env.DATABASE_URL) return reply(res,503,{ok:false,error:"database_not_configured"});
  if (!["GET","POST"].includes(req.method)) return reply(res,405,{ok:false,error:"method_not_allowed"},{Allow:"GET, POST"});
  const sql = neon(process.env.DATABASE_URL);
  const token = parseCookies(req.headers.cookie || "")[COOKIE];
  try {
    if (req.method === "GET") {
      if (!token) return reply(res,401,{ok:false,authenticated:false});
      const hash = crypto.createHash("sha256").update(token).digest("hex");
      const rows = await sql`SELECT u.username FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=${hash} AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true AND u.is_admin=true LIMIT 1`;
      if (!rows.length) return reply(res,401,{ok:false,authenticated:false},{ "Set-Cookie":setCookie("",0) });
      return reply(res,200,{ok:true,authenticated:true,username:rows[0].username});
    }
    const body = await bodyOf(req);
    if (body.action === "logout") {
      if (token) {
        const hash = crypto.createHash("sha256").update(token).digest("hex");
        await sql`UPDATE auth_sessions SET revoked_at=now() WHERE token_hash=${hash} AND revoked_at IS NULL`;
      }
      return reply(res,200,{ok:true},{ "Set-Cookie":setCookie("",0) });
    }
    const pin = String(body.pin || "");
    if (!/^\\d{6}$/.test(pin)) return reply(res,400,{ok:false,error:"pin_must_be_six_digits"});
    const ip = ipDigest(req);
    const attempt = await sql`SELECT failures,locked_until,updated_at FROM auth_attempts WHERE ip_hash=${ip} LIMIT 1`;
    if (attempt.length && attempt[0].locked_until && new Date(attempt[0].locked_until)>new Date()) return reply(res,429,{ok:false,error:"temporarily_locked"});
    const users = await sql`SELECT id,username,pin_hash FROM app_users WHERE active=true AND is_admin=true ORDER BY created_at ASC LIMIT 1`;
    const valid = users.length ? await verifyPin(pin,users[0].pin_hash) : false;
    if (!valid) {
      await sql`INSERT INTO auth_attempts(ip_hash,failures,locked_until,updated_at) VALUES(${ip},1,NULL,now())
        ON CONFLICT(ip_hash) DO UPDATE SET
        failures=CASE WHEN auth_attempts.updated_at < now()-interval '15 minutes' THEN 1 ELSE auth_attempts.failures+1 END,
        locked_until=CASE WHEN (CASE WHEN auth_attempts.updated_at < now()-interval '15 minutes' THEN 1 ELSE auth_attempts.failures+1 END)>=5 THEN now()+interval '15 minutes' ELSE NULL END,
        updated_at=now()`;
      return reply(res,401,{ok:false,error:"invalid_pin"});
    }
    await sql`INSERT INTO auth_attempts(ip_hash,failures,locked_until,updated_at) VALUES(${ip},0,NULL,now())
      ON CONFLICT(ip_hash) DO UPDATE SET failures=0,locked_until=NULL,updated_at=now()`;
    const session = crypto.randomBytes(32).toString("hex");
    const sessionHash = crypto.createHash("sha256").update(session).digest("hex");
    await sql`INSERT INTO auth_sessions(user_id,token_hash,expires_at) VALUES(${users[0].id},${sessionHash},now()+interval '7 days')`;
    return reply(res,200,{ok:true,authenticated:true,username:users[0].username},{ "Set-Cookie":setCookie(session,SESSION_SECONDS) });
  } catch (err) {
    console.error("Asia auth failure:",err?.message || "unknown");
    return reply(res,500,{ok:false,error:"server_error"});
  }
};