(function(){
  const { BACKEND_BASE, GOOGLE_CLIENT_ID, FLOW } = window.FANHUB_CONFIG;

  // === A. 팝업 플로우 (기본값) ===
  async function onGoogleCredentialPopup(resp){
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
    if (FLOW === "A") {
      google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: onGoogleCredentialPopup,
        ux_mode: "popup",
        // postMessage 관련 브라우저 이슈 회피용 (일부 환경에서 도움)
        use_fedcm_for_prompt: true
      });
      google.accounts.id.renderButton(
        document.getElementById("googleBtn"),
        { theme: "outline", size: "large", width: 260, type: "standard", shape: "rectangular" }
      );
    } else {
      // === B. 리다이렉트 플로우 ===
      google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        ux_mode: "redirect",
        login_uri: BACKEND_BASE + "/auth/google/redirect",
        use_fedcm_for_prompt: true
      });
      google.accounts.id.renderButton(
        document.getElementById("googleBtn"),
        { theme: "outline", size: "large", width: 260, type: "standard", shape: "rectangular" }
      );
    }

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