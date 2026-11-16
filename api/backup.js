const crypto=require("node:crypto");
const {neon}=require("@neondatabase/serverless");
const COOKIE="asia_admin_session";
function send(res,status,data){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data))}
function readCookie(header=""){for(const part of header.split(";")){const i=part.indexOf("=");if(i>0&&part.slice(0,i).trim()===COOKIE){try{return decodeURIComponent(part.slice(i+1).trim())}catch{return null}}}return null}
module.exports=async function(req,res){
 if(req.method!=="GET")return send(res,405,{ok:false,error:"method_not_allowed"});
 if(!process.env.DATABASE_URL)return send(res,503,{ok:false,error:"database_not_configured"});
 const token=readCookie(req.headers.cookie||"");
 if(!token||!/^[a-f0-9]{64}$/i.test(token))return send(res,401,{ok:false,error:"unauthorized"});
 const sql=neon(process.env.DATABASE_URL),hash=crypto.createHash("sha256").update(token).digest("hex");
 try{
  const sessions=await sql`SELECT u.workspace_id FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=${hash} AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true AND u.is_admin=true LIMIT 1`;
  if(!sessions.length)return send(res,401,{ok:false,error:"unauthorized"});
  const wid=sessions[0].workspace_id;
  const [settings,customers,rates,expenses,machineIncome,payments,products,purchases,purchaseItems,sales,saleItems,stockLayers,stockMovements,suppliers]=await Promise.all([
   sql`SELECT * FROM app_settings WHERE workspace_id=${wid} ORDER BY updated_at`,
   sql`SELECT * FROM customers WHERE workspace_id=${wid} ORDER BY created_at`,
   sql`SELECT * FROM exchange_rates WHERE workspace_id=${wid} ORDER BY effective_at,created_at`,
   sql`SELECT * FROM expenses WHERE workspace_id=${wid} ORDER BY spent_at`,
   sql`SELECT * FROM machine_income WHERE workspace_id=${wid} ORDER BY received_at`,
   sql`SELECT * FROM payments WHERE workspace_id=${wid} ORDER BY paid_at`,
   sql`SELECT * FROM products WHERE workspace_id=${wid} ORDER BY created_at`,
   sql`SELECT * FROM purchases WHERE workspace_id=${wid} ORDER BY purchased_at`,
   sql`SELECT pi.* FROM purchase_items pi JOIN purchases p ON p.id=pi.purchase_id WHERE p.workspace_id=${wid} ORDER BY pi.id`,
   sql`SELECT * FROM sales WHERE workspace_id=${wid} ORDER BY sold_at`,
   sql`SELECT si.* FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE s.workspace_id=${wid} ORDER BY si.id`,
   sql`SELECT * FROM stock_cost_layers WHERE workspace_id=${wid} ORDER BY received_at,id`,
   sql`SELECT * FROM stock_movements WHERE workspace_id=${wid} ORDER BY occurred_at,id`,
   sql`SELECT * FROM suppliers WHERE workspace_id=${wid} ORDER BY created_at`
  ]);
  const data={app_settings:settings,customers,exchange_rates:rates,expenses,machine_income:machineIncome,payments,products,purchases,purchase_items:purchaseItems,sales,sale_items:saleItems,stock_cost_layers:stockLayers,stock_movements:stockMovements,suppliers};
  const counts=Object.fromEntries(Object.entries(data).map(([k,v])=>[k,v.length]));
  return send(res,200,{ok:true,format:"asia-accounting-backup",version:1,created_at:new Date().toISOString(),workspace_id:wid,counts,data});
 }catch(error){console.error("Asia backup API error:",error?.message||"unknown");return send(res,500,{ok:false,error:"backup_failed"})}
};
