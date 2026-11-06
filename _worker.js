export default{async fetch(req,env){const u=new URL(req.url);
const bad=()=>new Response("no",{status:401});
const body=async()=>await req.json().catch(()=>({}));
if(u.pathname==="/api/menu"){
if(req.method==="GET"){const v=await env.MENU.get("menu");return new Response(v||"null",{headers:{"content-type":"application/json","cache-control":"no-store"}})}
if(req.method==="POST"){const b=await body();if(!env.ADMIN_PW||b.pw!==env.ADMIN_PW)return bad();await env.MENU.put("menu",JSON.stringify(b.data));return new Response("ok")}}
if(u.pathname==="/api/check"&&req.method==="POST"){const b=await body();return env.ADMIN_PW&&b.pw===env.ADMIN_PW?new Response("ok"):bad()}
return env.ASSETS.fetch(req)}}
