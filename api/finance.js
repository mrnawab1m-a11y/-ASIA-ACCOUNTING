const crypto=require("node:crypto");
const {neon}=require("@neondatabase/serverless");
const COOKIE="asia_admin_session";
function send(res,status,data){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data))}
function cookie(header=""){for(const part of header.split(";")){const i=part.indexOf("=");if(i>0&&part.slice(0,i).trim()===COOKIE){try{return decodeURIComponent(part.slice(i+1).trim())}catch{return null}}}return null}
async function body(req){if(req.body&&typeof req.body==="object")return req.body;let raw="";for await(const chunk of req){raw+=chunk;if(raw.length>12000)throw new Error("large")}try{return JSON.parse(raw||"{}")}catch{return {}}}
const clean=v=>String(v??"").trim();
const num=v=>{const n=Number(v);return Number.isFinite(n)?n:NaN};
module.exports=async function(req,res){
 if(!["GET","POST"].includes(req.method))return send(res,405,{error:"method_not_allowed"});
 if(!process.env.DATABASE_URL)return send(res,503,{error:"database_not_configured"});
 const token=cookie(req.headers.cookie||"");if(!token||!/^[a-f0-9]{64}$/i.test(token))return send(res,401,{error:"unauthorized"});
 if(req.method==="POST"){try{if(!req.headers.origin||!req.headers.host||new URL(req.headers.origin).host!==req.headers.host)return send(res,403,{error:"origin_not_allowed"})}catch{return send(res,403,{error:"origin_not_allowed"})}}
 const sql=neon(process.env.DATABASE_URL),hash=crypto.createHash("sha256").update(token).digest("hex");
 try{
  const auth=await sql`SELECT u.workspace_id FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=${hash} AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true AND u.is_admin=true LIMIT 1`;
  if(!auth.length)return send(res,401,{error:"unauthorized"});
  const wid=auth[0].workspace_id,action=new URL(req.url,"https://local.invalid").searchParams.get("action")||"";
  if(action==="expenses"){
   if(req.method==="GET"){
    const rows=await sql`SELECT id,title,amount,currency,exchange_rate,spent_at,notes,expense_scope,(amount*exchange_rate) AS amount_afn FROM expenses WHERE workspace_id=${wid} ORDER BY spent_at DESC LIMIT 200`;
    return send(res,200,{ok:true,expenses:rows});
   }
   let x;try{x=await body(req)}catch{return send(res,413,{error:"request_too_large"})}
   const title=clean(x.title),currency=clean(x.currency),amount=num(x.amount),rate=num(x.exchange_rate),notes=clean(x.notes),expenseScope=clean(x.expense_scope||"general");
   if(!title||title.length>160||!["AFN","USD","PKR"].includes(currency)||!Number.isFinite(amount)||amount<=0||!Number.isFinite(rate)||rate<=0||notes.length>1000||!["general","machine"].includes(expenseScope))return send(res,400,{error:"invalid_expense"});
   if(currency==="AFN"&&rate!==1)return send(res,400,{error:"afn_rate_must_be_one"});
   const rows=await sql`INSERT INTO expenses(workspace_id,title,amount,currency,exchange_rate,notes,expense_scope) VALUES(${wid},${title},${amount},${currency},${rate},NULLIF(${notes},''),${expenseScope}) RETURNING id,title,amount,currency,exchange_rate,spent_at,notes,expense_scope`;
   return send(res,201,{ok:true,expense:rows[0]});
  }
  if(action==="machine-income"){
   if(req.method==="GET"){
    const rows=await sql`SELECT id,amount,currency,exchange_rate,received_at,notes,(amount*exchange_rate) AS amount_afn FROM machine_income WHERE workspace_id=${wid} ORDER BY received_at DESC LIMIT 200`;
    return send(res,200,{ok:true,incomes:rows});
   }
   let x;try{x=await body(req)}catch{return send(res,413,{error:"request_too_large"})}
   const currency=clean(x.currency||"AFN"),amount=num(x.amount),rate=num(x.exchange_rate),notes=clean(x.notes);
   if(!["AFN","USD","PKR"].includes(currency)||!Number.isFinite(amount)||amount<=0||!Number.isFinite(rate)||rate<=0||notes.length>1000||(currency==="AFN"&&rate!==1))return send(res,400,{error:"invalid_machine_income"});
   const rows=await sql`INSERT INTO machine_income(workspace_id,amount,currency,exchange_rate,notes) VALUES(${wid},${amount},${currency},${rate},NULLIF(${notes},'')) RETURNING id,amount,currency,exchange_rate,received_at,notes,(amount*exchange_rate) AS amount_afn`;
   return send(res,201,{ok:true,income:rows[0]});
  }
  if(action==="rates"){
   if(req.method==="GET"){
    const rows=await sql`SELECT DISTINCT ON(base_currency) base_currency AS currency,rate,effective_at FROM exchange_rates WHERE workspace_id=${wid} AND quote_currency='AFN' ORDER BY base_currency,effective_at DESC,created_at DESC`;
    return send(res,200,{ok:true,rates:rows});
   }
   let x;try{x=await body(req)}catch{return send(res,413,{error:"request_too_large"})}
   const currency=clean(x.currency),rate=num(x.rate);
   if(!["USD","PKR"].includes(currency)||!Number.isFinite(rate)||rate<=0||rate>1000000)return send(res,400,{error:"invalid_rate"});
   const rows=await sql`INSERT INTO exchange_rates(workspace_id,base_currency,quote_currency,rate) VALUES(${wid},${currency},'AFN',${rate}) RETURNING base_currency AS currency,rate,effective_at`;
   return send(res,201,{ok:true,rate:rows[0]});
  }

  if(action==="customer-payment"||action==="supplier-payment"){
   if(req.method!=="POST")return send(res,405,{error:"method_not_allowed"});
   let x;try{x=await body(req)}catch{return send(res,413,{error:"request_too_large"})}
   const entityId=clean(action==="customer-payment"?x.customer_id:x.supplier_id),currency=clean(x.currency),amount=num(x.amount),rate=num(x.exchange_rate);
   if(!/^[0-9a-f-]{36}$/i.test(entityId)||!["AFN","USD","PKR"].includes(currency)||!Number.isFinite(amount)||amount<=0||!Number.isFinite(rate)||rate<=0||(currency==="AFN"&&rate!==1))return send(res,400,{error:"invalid_payment"});
   const customer=action==="customer-payment";
   const rows=customer?await sql`WITH entity AS (SELECT id FROM customers WHERE id=${entityId} AND workspace_id=${wid}), lock_row AS (SELECT pg_advisory_xact_lock(hashtextextended(${wid}::text||':customer:'||${entityId},0)) FROM entity), balance AS (SELECT COALESCE((SELECT SUM(s.total_amount*s.exchange_rate) FROM sales s WHERE s.customer_id=${entityId} AND s.workspace_id=${wid}),0)-COALESCE((SELECT SUM(p.amount*p.exchange_rate) FROM payments p WHERE p.customer_id=${entityId} AND p.workspace_id=${wid}),0) AS due FROM lock_row), inserted AS (INSERT INTO payments(workspace_id,customer_id,amount,currency,exchange_rate,notes) SELECT ${wid},${entityId},${amount},${currency},${rate},'دریافت پرداخت حساب مشتری' FROM balance WHERE due>=${amount*rate} AND due>0 RETURNING id,amount,currency,exchange_rate,paid_at) SELECT due,(SELECT row_to_json(i) FROM inserted i) AS payment FROM balance`:
   await sql`WITH entity AS (SELECT id FROM suppliers WHERE id=${entityId} AND workspace_id=${wid}), lock_row AS (SELECT pg_advisory_xact_lock(hashtextextended(${wid}::text||':supplier:'||${entityId},0)) FROM entity), balance AS (SELECT COALESCE((SELECT SUM(b.total_amount*b.exchange_rate) FROM purchases b WHERE b.supplier_id=${entityId} AND b.workspace_id=${wid}),0)-COALESCE((SELECT SUM(p.amount*p.exchange_rate) FROM payments p WHERE p.supplier_id=${entityId} AND p.workspace_id=${wid}),0) AS due FROM lock_row), inserted AS (INSERT INTO payments(workspace_id,supplier_id,amount,currency,exchange_rate,notes) SELECT ${wid},${entityId},${amount},${currency},${rate},'پرداخت حساب فروشنده' FROM balance WHERE due>=${amount*rate} AND due>0 RETURNING id,amount,currency,exchange_rate,paid_at) SELECT due,(SELECT row_to_json(i) FROM inserted i) AS payment FROM balance`;
   if(!rows.length)return send(res,404,{error:customer?"customer_not_found":"supplier_not_found"});
   if(!rows[0].payment)return send(res,400,{error:"payment_exceeds_balance",balance_afn:rows[0].due});
   return send(res,201,{ok:true,payment:rows[0].payment,balance_before_afn:rows[0].due});
  }
  if(action==="reports"){
   if(req.method!=="GET")return send(res,405,{error:"method_not_allowed"});
   const [summary,daily,stock,expenses,sales,purchases]=await Promise.all([
    sql`SELECT
     COALESCE((SELECT SUM(total_amount*exchange_rate) FROM sales WHERE workspace_id=${wid} AND (sold_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0) AS today_sales,
     COALESCE((SELECT SUM(gross_profit) FROM sales WHERE workspace_id=${wid} AND (sold_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0) AS today_profit,
     COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid} AND (spent_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0) AS today_expenses,
     COALESCE((SELECT SUM(gross_profit) FROM sales WHERE workspace_id=${wid} AND (sold_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0)
       + COALESCE((SELECT SUM(amount*exchange_rate) FROM machine_income WHERE workspace_id=${wid} AND (received_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0)
       - COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid} AND (spent_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0) AS today_net_profit,
     COALESCE((SELECT SUM(amount*exchange_rate) FROM machine_income WHERE workspace_id=${wid} AND (received_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0) AS today_machine_income,
     COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid} AND expense_scope='machine' AND (spent_at AT TIME ZONE 'Asia/Kabul')::date=(now() AT TIME ZONE 'Asia/Kabul')::date),0) AS today_machine_expenses,
     COALESCE((SELECT SUM(total_amount*exchange_rate) FROM sales WHERE workspace_id=${wid}),0) AS all_sales,
     COALESCE((SELECT SUM(gross_profit) FROM sales WHERE workspace_id=${wid}),0) AS all_gross_profit,
     COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid}),0) AS all_expenses,
     COALESCE((SELECT SUM(gross_profit) FROM sales WHERE workspace_id=${wid}),0)
       + COALESCE((SELECT SUM(amount*exchange_rate) FROM machine_income WHERE workspace_id=${wid}),0)
       - COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid}),0) AS all_net_profit,
     COALESCE((SELECT SUM(amount*exchange_rate) FROM machine_income WHERE workspace_id=${wid}),0) AS all_machine_income,
     COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid} AND expense_scope='machine'),0) AS all_machine_expenses`,
    sql`SELECT (sold_at AT TIME ZONE 'Asia/Kabul')::date AS day,COUNT(*)::int AS invoice_count,SUM(total_amount*exchange_rate) AS sales_afn,SUM(gross_profit) AS gross_profit_afn FROM sales WHERE workspace_id=${wid} AND sold_at>=now()-interval '30 days' GROUP BY (sold_at AT TIME ZONE 'Asia/Kabul')::date ORDER BY day DESC LIMIT 30`,
    sql`SELECT p.id,p.name,p.unit,COALESCE(SUM(m.quantity_delta),0) AS stock_quantity FROM products p LEFT JOIN stock_movements m ON m.product_id=p.id AND m.workspace_id=p.workspace_id WHERE p.workspace_id=${wid} AND p.active=true GROUP BY p.id,p.name,p.unit ORDER BY p.name`,
    sql`SELECT COUNT(*)::int AS count,COALESCE(SUM(amount*exchange_rate),0) AS total_afn FROM expenses WHERE workspace_id=${wid}`,
    sql`SELECT COUNT(*)::int AS count FROM sales WHERE workspace_id=${wid}`,
    sql`SELECT COUNT(*)::int AS count FROM purchases WHERE workspace_id=${wid}`
   ]);
   const machineCash=await sql`SELECT
     COALESCE((SELECT SUM(amount*exchange_rate) FROM payments WHERE workspace_id=${wid} AND customer_id IS NOT NULL),0)
     + COALESCE((SELECT SUM(amount*exchange_rate) FROM machine_income WHERE workspace_id=${wid}),0)
     - COALESCE((SELECT SUM(amount*exchange_rate) FROM payments WHERE workspace_id=${wid} AND supplier_id IS NOT NULL),0)
     - COALESCE((SELECT SUM(amount*exchange_rate) FROM expenses WHERE workspace_id=${wid}),0) AS cash_balance_afn`;
   return send(res,200,{ok:true,summary:summary[0],daily,stock,cashbox:machineCash[0],counts:{expenses:expenses[0],sales:sales[0],purchases:purchases[0]}});
  }
  return send(res,400,{error:"unknown_action"});
 }catch(error){console.error("Asia finance API error:",error?.message||"unknown");return send(res,500,{error:"server_error"})}
};