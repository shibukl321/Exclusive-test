(function(){
  const { BACKEND_BASE, GOOGLE_CLIENT_ID } = window.FANHUB_CONFIG;

  async function onGoogleCredential(resp){
    try{
      const res = await fetch(BACKEND_BASE + "/auth/google", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ credential: resp.credential })
      });
      if(!res.ok){
        const txt = await res.text().catch(()=> "");
        alert("로그인 실패: " + res.status + " / " + txt);
        return;
      }
      await showSession();
    }catch(e){
      alert("네트워크/CORS 오류: " + e);
    }
  }

  window.onload = async function(){
    google.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: onGoogleCredential,
      ux_mode: "popup"
    });
    google.accounts.id.renderButton(
      document.getElementById("googleBtn"),
      { theme: "outline", size: "large", width: 260 }
    );

    document.getElementById("checkSession").onclick = showSession;
    document.getElementById("logoutBtn").onclick = logout;

    document.getElementById("confForm").addEventListener("submit", async (e)=>{
      e.preventDefault();
      const form = new FormData(e.target);
      const res = await fetch(BACKEND_BASE + "/confession", {
        method: "POST",
        body: form,
        credentials: "include"
      });
      if(!res.ok){ alert("등록 실패"); return; }
      e.target.reset();
      await loadConfessions();
    });

    await showSession();
    await loadConfessions();
  };

  async function showSession(){
    const node = document.getElementById("loginResult");
    try{
      const me = await fetch(BACKEND_BASE + "/session", { credentials:"include" }).then(r=>r.json());
      node.textContent = me?.user?.email ? ("로그인: " + me.user.email) : "세션 없음";
    }catch(e){
      node.textContent = "세션 조회 실패: " + e;
    }
  }
  async function logout(){
    try{
      await fetch(BACKEND_BASE + "/auth/logout", { method:"POST", credentials:"include" });
      await showSession();
    }catch(e){
      alert("로그아웃 실패: " + e);
    }
  }
  async function loadConfessions(){
    const list = document.getElementById("confList");
    list.innerHTML = "";
    try{
      const data = await fetch(BACKEND_BASE + "/confession").then(r=>r.json());
      for(const it of (data.items||[])){
        const li = document.createElement("li");
        const d = new Date(it.ts);
        li.textContent = `[${d.toLocaleString()}] ${it.message}`;
        list.appendChild(li);
      }
    }catch(e){
      const li = document.createElement("li");
      li.textContent = "불러오기 실패: " + e;
      list.appendChild(li);
    }
  }
})();