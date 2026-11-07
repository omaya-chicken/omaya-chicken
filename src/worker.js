const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
const enc=new TextEncoder();
async function sha(s){const d=await crypto.subtle.digest("SHA-256",enc.encode(s));return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join("")}
function safeEqual(a,b){if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
async function checkPassword(pw,env){if(!env.ADMIN_PASSWORD)throw new Error("ADMIN_PASSWORD secret is not configured");const saved=await env.MENU_KV.get("admin_password_hash");const expected=saved||await sha(env.ADMIN_PASSWORD);return safeEqual(await sha(String(pw||"")),expected)}
async function api(req,env,url){
 if(req.method==="GET"&&url.pathname==="/api/menu"){
  const saved=await env.MENU_KV.get("menu");
  if(saved){try{return json(JSON.parse(saved))}catch{return json({error:"بيانات المنيو المحفوظة تالفة"},500)}}
  const r=await env.ASSETS.fetch(new Request(new URL("/menu-default.json",url.origin)));
  if(!r.ok)return json({error:"تعذر تحميل بيانات المنيو الافتراضية"},500);
  return new Response(r.body,{headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}})
 }
 if(req.method==="POST"&&url.pathname==="/api/check"){
  const b=await req.json().catch(()=>({}));
  return await checkPassword(b.pw,env)?json({ok:true}):json({error:"كلمة المرور غير صحيحة"},401)
 }
 if(req.method==="POST"&&url.pathname==="/api/menu"){
  const b=await req.json().catch(()=>null);
  if(!b||!await checkPassword(b.pw,env))return json({error:"كلمة المرور غير صحيحة"},401);
  if(!b.data||!Array.isArray(b.data.s))return json({error:"بنية بيانات المنيو غير صحيحة"},400);
  const serialized=JSON.stringify(b.data);
  if(serialized.length>20000000)return json({error:"حجم المنيو كبير جداً؛ قلّل حجم الصور"},413);
  if(b.data.s.length>100||b.data.s.some(sec=>!sec||typeof sec.n!=="string"||!Array.isArray(sec.i)||sec.i.length>500))return json({error:"تركيب الأقسام غير صالح"},400);
  if(b.data.s.some(sec=>sec.i.some(it=>!Array.isArray(it)||typeof it[0]!=="string"||!Number.isFinite(Number(it[1]))||(it[2]!==undefined&&typeof it[2]!=="string")||(it[3]!==undefined&&typeof it[3]!=="string"))))return json({error:"بيانات أحد الأصناف غير صالحة"},400);
  await env.MENU_KV.put("menu",JSON.stringify(b.data));return json({ok:true})
 }
 if(req.method==="POST"&&url.pathname==="/api/password"){
  const b=await req.json().catch(()=>({}));
  if(!await checkPassword(b.currentPassword,env))return json({error:"كلمة المرور الحالية غير صحيحة"},403);
  if(typeof b.newPassword!=="string"||b.newPassword.length<10)return json({error:"استخدم كلمة مرور من 10 أحرف على الأقل"},400);
  await env.MENU_KV.put("admin_password_hash",await sha(b.newPassword));return json({ok:true})
 }
 return json({error:"المسار غير موجود"},404)
}
export default {async fetch(req,env){const url=new URL(req.url);try{if(url.pathname.startsWith("/api/"))return await api(req,env,url);return env.ASSETS.fetch(req)}catch(e){return json({error:"خطأ في إعداد الخادم: "+(e.message||"غير معروف")},500)}}};
