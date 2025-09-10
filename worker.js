
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGIN || "").split(",").map(s=>s.trim()).filter(Boolean);
    const corsOK = allowed.includes(origin);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": corsOK ? origin : "*",
          "Access-Control-Allow-Credentials": corsOK ? "true" : "false",
          "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Vary": "Origin"
        }
      });
    }

    const send = (data, init={})=>{
      const headers = init.headers || {};
      headers["content-type"] = (init.contentType || "application/json; charset=utf-8");
      headers["Access-Control-Allow-Origin"] = corsOK ? origin : "*";
      headers["Access-Control-Allow-Credentials"] = corsOK ? "true" : "false";
      headers["Vary"] = "Origin";
      return new Response(typeof data === "string" ? data : JSON.stringify(data), {status:init.status||200, headers});
    };

    const cookies = Object.fromEntries((request.headers.get("Cookie")||"").split(";").map(s=>s.trim().split("=")).filter(x=>x[0]));
    const sid = cookies["sid"] || "";

    async function kvGetJSON(key, def){
      let v = await env.FANHUB.get(key);
      if(!v) return def;
      try { return JSON.parse(v); } catch { return def; }
    }
    async function kvPutJSON(key, obj, opts){
      await env.FANHUB.put(key, JSON.stringify(obj), opts);
    }

    async function readSession(){
      if(!sid) return null;
      const sess = await kvGetJSON("sess:"+sid, null);
      if(!sess) return null;
      const admins = (env.ADMINS||"").split(",").map(s=>s.trim().toLowerCase());
      sess.isAdmin = admins.includes((sess.user?.email||"").toLowerCase());
      return sess;
    }

    if (url.pathname === "/session" && request.method === "GET") {
      const sess = await readSession();
      return send(sess || {});
    }

    if (url.pathname === "/auth/google" && request.method === "POST") {
      const ctype = request.headers.get("content-type") || "";
      let credential="";
      if (ctype.includes("application/x-www-form-urlencoded")) {
        const form = await request.formData();
        credential = form.get("credential") || "";
      } else if (ctype.includes("application/json")) {
        const j = await request.json().catch(()=>({}));
        credential = j.credential || "";
      }
      if (!credential) return send({ok:false, error:"missing credential"}, {status:400});

      const ver = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(credential));
      if (!ver.ok) return send({ok:false, error:"google verify failed"}, {status:401});
      const info = await ver.json();

      if (info.aud !== env.GOOGLE_CLIENT_ID) {
        return send({ok:false, error:"audience mismatch"}, {status:401});
      }
      if (info.email_verified !== "true" && info.email_verified !== true) {
        return send({ok:false, error:"email not verified"}, {status:401});
      }

      const email = info.email;
      const newSid = cryptoRandom();
      const user = { email, name: info.name || email.split("@")[0], picture: info.picture || "" };
      await kvPutJSON("sess:"+newSid, { user, ts: Date.now() }, {expirationTtl: 60*60*24*30});
      const cookie = `sid=${newSid}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${60*60*24*30}`;
      return new Response(JSON.stringify({ok:true}), {
        status: 200,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "set-cookie": cookie,
          "Access-Control-Allow-Origin": corsOK ? origin : "*",
          "Access-Control-Allow-Credentials": corsOK ? "true" : "false",
          "Vary": "Origin"
        }
      });
    }

    if (url.pathname === "/auth/logout" && request.method === "POST") {
      if (sid) await env.FANHUB.delete("sess:"+sid);
      const cookie = `sid=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
      return new Response(JSON.stringify({ok:true}), {
        status: 200,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "set-cookie": cookie,
          "Access-Control-Allow-Origin": corsOK ? origin : "*",
          "Access-Control-Allow-Credentials": corsOK ? "true" : "false",
          "Vary": "Origin"
        }
      });
    }

    // prefs
    if (url.pathname === "/prefs/fav" && request.method === "POST") {
      const sess = await readSession(); if(!sess) return send({ok:false, error:"login required"},{status:401});
      const form = await request.formData();
      const key = (form.get("key")||"").trim();
      const ukey = "user:"+sess.user.email;
      const data = await kvGetJSON(ukey, { favs:[] });
      if(!data.favs.includes(key)) data.favs.push(key);
      await kvPutJSON(ukey, data);
      await kvPutJSON("sess:"+sid, { ...sess, prefs: data }, {expirationTtl: 60*60*24*30});
      return send({ok:true, prefs:data});
    }

    // live
    if (url.pathname === "/live") {
      if (request.method === "GET") {
        const v = await kvGetJSON("live:list", []);
        return send({live: v});
      } else if (request.method === "POST") {
        const sess = await readSession(); if(!sess?.isAdmin) return send({ok:false},{status:403});
        const form = await request.formData();
        const key = (form.get("key")||"").trim();
        const on = (form.get("on")||"") === "true";
        let list = await kvGetJSON("live:list", []);
        const set = new Set(list);
        if (on) set.add(key); else set.delete(key);
        await kvPutJSON("live:list", Array.from(set));
        return send({ok:true});
      }
    }

    // gallery
    if (url.pathname === "/gallery" && request.method === "GET") {
      const items = [];
      const pins = await kvGetJSON("gallery:pins", {});
      for (const [member, urlx] of Object.entries(pins)) {
        items.push({member, memberName: member, url: urlx, tag:"pin", caption:"관리자 고정"});
      }
      const pool = await kvGetJSON("gallery:seeds", []);
      shuffle(pool);
      for (const it of pool.slice(0, Math.max(0, 3 - items.length))) {
        items.push(it);
      }
      return send({items});
    }
    if (url.pathname === "/gallery/seed" && request.method === "POST") {
      const sess = await readSession(); if(!sess?.isAdmin) return send({ok:false},{status:403});
      const form = await request.formData();
      const key = (form.get("key")||"").trim();
      const urlx = (form.get("url")||"").trim();
      const seeds = await kvGetJSON("gallery:seeds", []);
      seeds.push({member:key, memberName:key, url:urlx, tag:"seed", caption:""});
      await kvPutJSON("gallery:seeds", seeds);
      return send({ok:true});
    }
    if (url.pathname === "/gallery/pin" && request.method === "POST") {
      const sess = await readSession(); if(!sess?.isAdmin) return send({ok:false},{status:403});
      const form = await request.formData();
      const key = (form.get("key")||"").trim();
      const urlx = (form.get("url")||"").trim();
      const pins = await kvGetJSON("gallery:pins", {});
      pins[key] = urlx;
      await kvPutJSON("gallery:pins", pins);
      return send({ok:true});
    }
    if (url.pathname === "/img" && request.method === "GET") {
      const src = url.searchParams.get("url") || "";
      if (!/^https?:\/\//i.test(src)) return send("bad url", {status:400, contentType:"text/plain"});
      const prox = await fetch(src, { cf: { cacheTtl: 3600, cacheEverything: true } });
      const resp = new Response(prox.body, prox);
      const headers = new Headers(resp.headers);
      headers.set("Access-Control-Allow-Origin", corsOK ? origin : "*");
      headers.set("Access-Control-Allow-Credentials", corsOK ? "true" : "false");
      headers.set("Vary","Origin");
      return new Response(resp.body, {status: resp.status, headers});
    }

    // vote
    if (url.pathname === "/vote/state" && request.method === "GET") {
      const now = new Date();
      const y = now.getFullYear(), m = String(now.getMonth()+1).padStart(2,"0");
      const bucket = `vote:${y}-${m}`;
      const sess = await readSession();
      let voted = false;
      if (sess?.user?.email) {
        const v = await kvGetJSON(bucket+":users", {});
        voted = !!v[sess.user.email];
      }
      const msg = `투표 기간: 매월 1일~말일 · 현재 ${y}-${m}` + (voted?" · 이미 투표 완료":" · 아직 투표 가능");
      return send({message: msg, voted});
    }
    if (url.pathname === "/vote" && request.method === "POST") {
      const now = new Date();
      const y = now.getFullYear(), m = String(now.getMonth()+1).padStart(2,"0");
      const bucket = `vote:${y}-${m}`;
      const sess = await readSession(); if(!sess) return send({ok:false,error:"login required"},{status:401});
      const form = await request.formData();
      const key = (form.get("key")||"").trim();
      const users = await kvGetJSON(bucket+":users", {});
      if (users[sess.user.email]) return send({ok:false, message:"이미 이번 달에 투표했습니다."},{status:400});
      users[sess.user.email] = key;
      await kvPutJSON(bucket+":users", users);
      const counts = await kvGetJSON(bucket+":counts", {});
      counts[key] = (counts[key]||0)+1;
      await kvPutJSON(bucket+":counts", counts);
      return send({ok:true, message:"투표가 저장되었습니다."});
    }
    if (url.pathname === "/vote/results" && request.method === "GET") {
      const now = new Date();
      const y = now.getFullYear(), m = String(now.getMonth()+1).padStart(2,"0");
      const bucket = `vote:${y}-${m}`;
      const counts = await kvGetJSON(bucket+":counts", {});
      const results = Object.entries(counts).map(([key,count])=>({key, count})).sort((a,b)=>b.count-a.count);
      return send({results});
    }

    // diary
    if (url.pathname === "/diary" && request.method === "GET") {
      const sess = await readSession(); if(!sess) return send({items:[]});
      const key = "diary:"+sess.user.email;
      const items = await kvGetJSON(key, []);
      return send({items});
    }
    if (url.pathname === "/diary" && request.method === "POST") {
      const sess = await readSession(); if(!sess) return send({ok:false},{status:401});
      const form = await request.formData();
      const item = { id: cryptoRandom(), ts: Date.now(), title: (form.get("title")||"").slice(0,120), body: (form.get("body")||"").slice(0,4000) };
      const key = "diary:"+sess.user.email;
      const items = await kvGetJSON(key, []);
      items.unshift(item);
      await kvPutJSON(key, items);
      return send({ok:true, item});
    }
    if (url.pathname.startsWith("/diary/") && request.method === "DELETE") {
      const sess = await readSession(); if(!sess) return send({ok:false},{status:401});
      const id = url.pathname.split("/").pop();
      const key = "diary:"+sess.user.email;
      let items = await kvGetJSON(key, []);
      items = items.filter(x=>x.id!==id);
      await kvPutJSON(key, items);
      return send({ok:true});
    }

    // confession
    if (url.pathname === "/confession" && request.method === "GET") {
      const items = await kvGetJSON("confession:list", []);
      return send({items});
    }
    if (url.pathname === "/confession" && request.method === "POST") {
      const form = await request.formData();
      const msg = (form.get("message")||"").toString().slice(0, 2000);
      if(!msg) return send({ok:false, error:"empty"}, {status:400});
      let items = await kvGetJSON("confession:list", []);
      const it = { id: cryptoRandom(), ts: Date.now(), message: msg };
      items.unshift(it);
      await kvPutJSON("confession:list", items);
      return send({ok:true, item: it});
    }
    if (url.pathname.startsWith("/confession/") && request.method === "DELETE") {
      const sess = await readSession(); if(!sess?.isAdmin) return send({ok:false},{status:403});
      const id = url.pathname.split("/").pop();
      let items = await kvGetJSON("confession:list", []);
      items = items.filter(x=>x.id!==id);
      await kvPutJSON("confession:list", items);
      return send({ok:true});
    }

    return send({ok:false, error:"not_found"}, {status:404});
  }
};

function cryptoRandom(){
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return Array.from(a).map(b=>b.toString(16).padStart(2,"0")).join("");
}
function shuffle(arr){
  for(let i=arr.length-1;i>0;i--){ const j=(Math.random()*(i+1))|0; [arr[i],arr[j]]=[arr[j],arr[i]]; }
}
