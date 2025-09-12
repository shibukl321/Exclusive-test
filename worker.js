export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ====== CORS ======
    const reqOrigin = request.headers.get("Origin") || "";
    const allowedList = (env.ALLOWED_ORIGIN || "")
      .split(",").map(s=>s.trim()).filter(Boolean);
    const corsOK = allowedList.includes(reqOrigin);

    function baseCorsHeaders(ok) {
      const h = new Headers();
      h.set("Access-Control-Allow-Origin", ok ? reqOrigin : "*");
      h.set("Access-Control-Allow-Credentials", ok ? "true" : "false");
      h.set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
      h.set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Accept");
      h.set("Access-Control-Max-Age", "86400");
      h.set("Vary", "Origin");
      h.set("X-Content-Type-Options", "nosniff");
      h.set("Referrer-Policy", "no-referrer");
      h.set("X-Debug-Origin", reqOrigin || "-");
      h.set("X-Allowed-Origins", allowedList.join(",") || "-");
      return h;
    }
    const send = (data, init={}) => {
      const headers = baseCorsHeaders(corsOK);
      headers.set("content-type", init.contentType || "application/json; charset=utf-8");
      if (init.headers) for (const [k,v] of Object.entries(init.headers)) headers.set(k, v);
      return new Response(typeof data === "string" ? data : JSON.stringify(data), { status: init.status || 200, headers });
    };

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: baseCorsHeaders(corsOK) });

    // ===== utils =====
    const cookies = Object.fromEntries((request.headers.get("Cookie")||"").split(";").map(s=>s.trim().split("=")).filter(x=>x[0]));
    const sid = cookies["sid"] || "";
    async function kvGetJSON(key, defVal){ const v = await env.FANHUB.get(key); if(!v) return defVal; try {return JSON.parse(v);} catch {return defVal;} }
    async function kvPutJSON(key, obj, opts){ await env.FANHUB.put(key, JSON.stringify(obj), opts); }
    function rid(){ const a=new Uint8Array(16); crypto.getRandomValues(a); return [...a].map(b=>b.toString(16).padStart(2,"0")).join(""); }
    async function readSession(){
      if(!sid) return null;
      const sess = await kvGetJSON("sess:"+sid, null);
      if(!sess) return null;
      const admins = (env.ADMINS||"").split(",").map(s=>s.trim().toLowerCase());
      sess.isAdmin = admins.includes((sess.user?.email||"").toLowerCase());
      return sess;
    }

    // ===== debug =====
    if (url.pathname === "/health") return send({ ok: true });
    if (url.pathname === "/debug/cors") return send({ reqOrigin, allowedList, corsOK });
    if (url.pathname === "/debug/headers") {
      const all = {}; for (const [k,v] of request.headers.entries()) all[k]=v; return send({ headers: all });
    }

    // ===== session =====
    if (url.pathname === "/session" && request.method === "GET") {
      const sess = await readSession(); return send(sess || {});
    }

    // ===== helper to verify Google ID token =====
    async function verifyTokenAndSetCookie(credential) {
      if (!credential) return { ok:false, status:400, body:{ error:"missing credential" } };

      const ver = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(credential), { cf:{cacheTtl:0} });
      if (!ver.ok) return { ok:false, status:401, body:{ error:"google verify failed" } };
      const info = await ver.json();
      if (info.aud !== env.GOOGLE_CLIENT_ID) return { ok:false, status:401, body:{ error:"audience mismatch" } };
      if (info.email_verified !== "true" && info.email_verified !== true) return { ok:false, status:401, body:{ error:"email not verified" } };

      const user = { email: info.email, name: info.name || info.email.split("@")[0], picture: info.picture || "" };
      const newsid = rid();
      await kvPutJSON("sess:"+newsid, { user, ts: Date.now() }, { expirationTtl: 60*60*24*30 });
      const cookie = `sid=${newsid}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${60*60*24*30}`;
      return { ok:true, cookie };
    }

    // ===== Google login: popup(flow from frontend) =====
    if (url.pathname === "/auth/google" && request.method === "POST") {
      let credential = "";
      const ct = request.headers.get("content-type") || "";
      if (ct.includes("application/x-www-form-urlencoded")) {
        const form = await request.formData(); credential = form.get("credential") || "";
      } else if (ct.includes("application/json")) {
        const j = await request.json().catch(()=>({})); credential = j.credential || "";
      } else {
        const form = await request.formData().catch(()=>null); if(form) credential = form.get("credential") || "";
      }

      const result = await verifyTokenAndSetCookie(credential);
      if (!result.ok) return send(result.body, { status: result.status });

      const headers = baseCorsHeaders(corsOK);
      headers.set("content-type","application/json; charset=utf-8");
      headers.set("cache-control","no-store");
      headers.set("set-cookie", result.cookie);
      return new Response(JSON.stringify({ ok:true }), { status:200, headers });
    }

    // ===== Google login: redirect(flow from google directly) =====
    // configure front-end with ux_mode:'redirect', login_uri: BACKEND_BASE + '/auth/google/redirect'
    // Google will POST credential to this endpoint, then we redirect back to FRONTEND_BASE.
    if (url.pathname === "/auth/google/redirect" && request.method === "POST") {
      const form = await request.formData().catch(()=>null);
      const credential = form?.get("credential") || "";
      const result = await verifyTokenAndSetCookie(credential);
      if (!result.ok) {
        const h = new Headers();
        h.set("content-type", "text/html; charset=utf-8");
        return new Response(`<!doctype html><meta charset="utf-8"><p>로그인 실패: ${result.body.error}</p>`, { status: 401, headers: h });
      }
      const h = new Headers();
      h.set("content-type","text/html; charset=utf-8");
      h.set("set-cookie", result.cookie);
      const dest = env.FRONTEND_BASE || "/";
      return new Response(`<!doctype html><meta charset="utf-8"><script>location.replace(${JSON.stringify(dest)});</script>`, { status: 200, headers: h });
    }

    if (url.pathname === "/auth/logout" && request.method === "POST") {
      if (sid) await env.FANHUB.delete("sess:"+sid);
      const headers = baseCorsHeaders(corsOK);
      headers.set("content-type","application/json; charset=utf-8");
      headers.set("set-cookie","sid=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0");
      return new Response(JSON.stringify({ ok:true }), { status:200, headers });
    }

    // confession example
    if (url.pathname === "/confession" && request.method === "GET") {
      const items = (await kvGetJSON("confession:list", [])) || []; return send({ items });
    }
    if (url.pathname === "/confession" && request.method === "POST") {
      const form = await request.formData(); const msg=(form.get("message")||"").toString().slice(0,2000);
      if(!msg) return send({ ok:false, error:"empty" }, { status:400 });
      let items = (await kvGetJSON("confession:list", [])) || []; const it = { id: rid(), ts: Date.now(), message: msg };
      items.unshift(it); await kvPutJSON("confession:list", items); return send({ ok:true, item: it });
    }

    return send({ ok:false, error:"not_found" }, { status:404 });
  },
};
