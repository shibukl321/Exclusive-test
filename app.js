
const q = (s, r=document)=>r.querySelector(s);
const qa = (s, r=document)=>Array.from(r.querySelectorAll(s));
const esc = (t)=> (t||'').replace(/[<>&]/g, m=>({ '<':'&lt;','>':'&gt;','&':'&amp;' }[m]));

const MEMBERS = [
  {key:'kanna', name:'아이리 칸나', group:'Stellive'},
  {key:'yuni', name:'아야츠노 유니', group:'Stellive'},
  {key:'hina', name:'시라유키 히나', group:'Stellive'},
  {key:'mashiro', name:'네네코 마시로', group:'Stellive'},
  {key:'lize', name:'아카네 리제', group:'Stellive'},
  {key:'tabi', name:'아라하시 타비', group:'Stellive'},
  {key:'shibuki', name:'텐코 시부키', group:'Stellive'},
  {key:'rin', name:'아오쿠모 린', group:'Stellive'},
  {key:'nana', name:'하나코 나나', group:'Stellive'},
  {key:'riko', name:'유즈하 리코', group:'Stellive'},
  {key:'jing', name:'징버거', group:'Isegye'},
  {key:'ine', name:'아이네', group:'Isegye'},
  {key:'lilpa', name:'릴파', group:'Isegye'},
  {key:'viichan', name:'비챤', group:'Isegye'},
  {key:'jururu', name:'주르르', group:'Isegye'},
  {key:'gosegu', name:'고세구', group:'Isegye'},
];

const STREAMS = {
  shibuki:"https://chzzk.naver.com/64d76089fba26b180d9c9e48a32600d9",
  riko:"https://chzzk.naver.com/8fd39bb8de623317de90654718638b10",
  nana:"https://chzzk.naver.com/4d812b586ff63f8a2946e64fa860bbf5",
  rin:"https://chzzk.naver.com/516937b5f85cbf2249ce31b0ad046b0f",
  lize:"https://chzzk.naver.com/4325b1d5bbc321fad3042306646e2e50",
  yuni:"https://chzzk.naver.com/45e71a76e949e16a34764deb962f9d9f",
  hina:"https://chzzk.naver.com/b044e3a3b9259246bc92e863e7d3f3b8",
  mashiro:"https://chzzk.naver.com/4515b179f86b67b4981e16190817c580",
  tabi:"https://chzzk.naver.com/a6c4ddb09cdb160478996007bff35296",
  gosegu:"https://ch.sooplive.co.kr/gosegu2",
  lilpa:"https://ch.sooplive.co.kr/lilpa0309",
  jururu:"https://ch.sooplive.co.kr/cotton1217",
  viichan:"https://ch.sooplive.co.kr/viichan6",
  jing:"https://ch.sooplive.co.kr/jingburger1",
  ine:"https://ch.sooplive.co.kr/inehine",
  kanna:"https://www.youtube.com/@airikannach/streams"
};

const PLAYLISTS = {
  riko:"https://www.youtube.com/playlist?list=PL_D2YrKeYY2UvRIw_SW3lQXzBDO7aBeii",
  shibuki:"https://www.youtube.com/playlist?list=PLKVNBOcsLJlVii-8YwoZTD3o4gh5CnIND",
  nana:"https://www.youtube.com/playlist?list=PLJWmDIpvwe7Cri29xtAyQXLC1RLwOChpA",
  hina:"https://www.youtube.com/playlist?list=PLzdLDJsHzz2NiuwjyW6QgSck4PrwlSyOc",
  kanna:"https://www.youtube.com/playlist?list=PLOPBV2KAIYnt1NJ0QCkfCqMRc00lfcjFa",
  lize:"https://www.youtube.com/playlist?list=PL-DHk0WpiRNSM5oI19ImJ8sSV65mnGseX",
  yuni:"https://www.youtube.com/playlist?list=PL3HtH_xx9h_7ZGoZ9zMUQ-MPumwe21_cc",
  tabi:"https://www.youtube.com/playlist?list=PLbIDsfX2JRA0oawGN209gpd_nz9IMvUlb",
  shiro:"https://www.youtube.com/playlist?list=PLWwhuXFHGLvhgZZb5_rmQEMI1B0ysKJxG",
  rin:"https://www.youtube.com/playlist?list=PLSDRWR15h-o4uWNeoLv0upOUUGj12f-yU",
  gosegu:"https://www.youtube.com/playlist?list=PLZNwpHxpI4EjDSv3v_HY7udxDEqj4C7PL",
  jururu:"https://www.youtube.com/playlist?list=PLqE7uvTHaH31Wl8lCe3SYslZvoCnTD-JS",
  viichan:"https://www.youtube.com/playlist?list=PLhaJuLneKo5FdYnMZ1Jc5BaV7y26KvmD1",
  jing:"https://www.youtube.com/playlist?list=PLio0a5EPF6j099Af5uBaK6V25RtTvK4kq",
  lilpa:"https://www.youtube.com/playlist?list=PLLPGQs-RNQXnFl55WissjQylZbInOK81P",
  ine:"https://www.youtube.com/playlist?list=PLJWTWXJ7iqXctxVu1Fd3ZkF-WWD8kOzMb"
};

function applySessionUI(session){
  const userBox = q('#userBox');
  const btnLogout = q('#btnLogout');
  if(session?.user){
    userBox.textContent = session.user.email + ' 로그인됨';
    btnLogout.classList.remove('hidden');
  }else{
    userBox.textContent = '로그인 안됨';
    btnLogout.classList.add('hidden');
  }
  const admin = q('#adminArea'); const gate = q('#adminGate');
  if(admin && gate){ if(session?.isAdmin){admin.classList.remove('hidden');gate.classList.add('hidden')} else {admin.classList.add('hidden');gate.classList.remove('hidden')} }
}

async function fetchSession(){
  try{
    const r = await fetch(window.BACKEND_BASE + '/session',{credentials:'include'});
    return await r.json();
  }catch(e){ return null }
}

function initGoogle(){
  if (window.__gsi_inited) return;
  window.__gsi_inited = true;

  const cid = window.GOOGLE_AUDIENCE;
  const mount = document.getElementById('gsiBtn');
  const fallback = document.getElementById('btnLoginFallback');

  if (fallback) {
    fallback.addEventListener('click', () => {
      if (window.google?.accounts?.id) {
        window.google.accounts.id.prompt(() => {});
      } else {
        alert('Google SDK 로딩 지연 중입니다. 잠시 후 다시 시도해 주세요.');
      }
    });
  }

  if (!window.google?.accounts?.id || !cid) return;

  window.google.accounts.id.initialize({
    client_id: cid,
    callback: async (res) => {
      try{
        const r = await fetch(window.BACKEND_BASE + '/auth/google', {
          method: 'POST',
          body: new URLSearchParams({ credential: res.credential }),
          credentials: 'include'
        });
        const j = await r.json().catch(()=>({ok:false,error:'json parse fail'}));
        if(j.ok) location.reload();
        else alert('로그인 실패: ' + (j.error||'알 수 없음'));
      }catch(e){ alert('네트워크 또는 CORS 오류: ' + e + '\n1) Google 콘솔 origin 등록 2) 백엔드 CORS(Allow-Credentials/Origin) 확인'); }
    }
  });

  if (mount) {
    mount.innerHTML='';
    window.google.accounts.id.renderButton(mount, { theme:'filled_blue', size:'large', shape:'pill', text:'continue_with' });
  }
  window.google.accounts.id.prompt(() => {});
}

async function logout(){
  await fetch(window.BACKEND_BASE + '/auth/logout',{method:'POST',credentials:'include'});
  location.reload();
}

function initTheme(){
  const radios = qa('input[name="theme"]');
  const saved = localStorage.getItem('theme') || 'stellive';
  document.documentElement.dataset.theme = saved;
  radios.forEach(r=>{
    r.checked = r.value===saved;
    r.addEventListener('change',()=>{
      localStorage.setItem('theme', r.value);
      document.documentElement.dataset.theme = r.value;
    });
  });
}

function renderMembers(session){
  const grid = q('#membersGrid'); if(!grid) return;
  grid.innerHTML='';
  MEMBERS.forEach(m=>{
    const favOn = (session?.prefs?.favs||[]).includes(m.key);
    const el = document.createElement('div'); el.className='card';
    el.innerHTML = `
      <div class="head"><strong>${m.name}</strong><span class="small">${m.group}</span></div>
      <img class="resp" src="https://picsum.photos/seed/${m.key}/800/480" alt="${m.name}"/>
      <div class="body">
        <div class="row">
          <a class="btn" href="${STREAMS[m.key]||'#'}" target="_blank">방송/채널</a>
          <a class="btn" href="${PLAYLISTS[m.key]||'#'}" target="_blank">커버곡</a>
          <button class="btn ${favOn?'primary':''}" data-fav="${m.key}">${favOn?'★ 즐겨찾기됨':'☆ 즐겨찾기'}</button>
        </div>
      </div>`;
    grid.appendChild(el);
  });
  qa('[data-fav]').forEach(btn=> btn.addEventListener('click', async ()=>{
    const key = btn.getAttribute('data-fav');
    const r = await fetch(window.BACKEND_BASE + '/prefs/fav', {
      method:'POST', credentials:'include', body:new URLSearchParams({ key })
    });
    const j = await r.json(); if(j.ok) location.reload(); else alert('로그인 필요/오류');
  }));
}

async function loadLive(){
  const box = q('#liveNowBox'); const badge=q('#liveBadge'); if(!box) return;
  try{
    const r = await fetch(window.BACKEND_BASE + '/live'); const j = await r.json();
    box.innerHTML='';
    let any=false;
    (j.live||[]).forEach(k=>{
      const m = MEMBERS.find(x=>x.key===k); if(!m) return;
      any=true;
      const row = document.createElement('div'); row.className='row';
      row.innerHTML = `<span class="live">●</span> <a target="_blank" href="${STREAMS[k]||'#'}">${m.name}</a>`;
      box.appendChild(row);
    });
    if(!any){ box.innerHTML = '<div class="small">지금은 표시된 라이브가 없어요.</div>'; badge.classList.add('hidden'); }
    else { badge.classList.remove('hidden'); }
  }catch(e){
    box.innerHTML = '<div class="small">불러오기 실패</div>';
  }
}

async function loadGallery(){
  const grid=q('#galleryGrid'); if(!grid) return;
  grid.innerHTML = '<div class="row"><div class="spinner"></div><span class="small">불러오는 중…</span></div>';
  try{
    const r = await fetch(window.BACKEND_BASE + '/gallery'); const j = await r.json();
    grid.innerHTML='';
    (j.items||[]).forEach(it=>{
      const src = window.BACKEND_BASE + '/img?url=' + encodeURIComponent(it.url);
      const el = document.createElement('div'); el.className='card';
      el.innerHTML = `<div class="head"><strong>${it.memberName}</strong><span class="small">${it.tag||''}</span></div>
        <img class="resp" loading="lazy" src="${src}" alt="fanart"/>
        <div class="body small">${esc(it.caption)}</div>`;
      grid.appendChild(el);
    });
    if(!grid.children.length){ grid.innerHTML='<div class="small">표시할 이미지가 아직 없어요.</div>'; }
  }catch(e){ grid.innerHTML='<div class="small">갤러리 로딩 실패</div>'; }
}

async function loadVote(){
  const list=q('#voteList'); const table=q('#voteTable tbody'); const state=q('#voteState');
  if(!list) return;
  try{
    const r = await fetch(window.BACKEND_BASE + '/vote/state',{credentials:'include'});
    const j = await r.json(); state.textContent = j.message||'';
  }catch(e){ state.textContent='상태 로딩 실패'; }
  list.innerHTML='';
  MEMBERS.forEach(m=>{
    const el = document.createElement('div'); el.className='card';
    el.innerHTML = `<div class="head"><strong>${m.name}</strong><span class="small">${m.group}</span></div>
      <div class="body"><button class="btn" data-vote="${m.key}">이 멤버에 투표</button></div>`;
    list.appendChild(el);
  });
  qa('[data-vote]').forEach(b=> b.addEventListener('click', async ()=>{
    const key = b.getAttribute('data-vote');
    try{
      const r = await fetch(window.BACKEND_BASE + '/vote', {
        method:'POST', credentials:'include', body:new URLSearchParams({ key })
      });
      const j = await r.json();
      alert(j.message || (j.ok?'투표 완료':'투표 실패'));
      loadVote();
    }catch(e){ alert('네트워크 오류'); }
  }));
  try{
    const r2 = await fetch(window.BACKEND_BASE + '/vote/results'); const res = await r2.json();
    table.innerHTML='';
    (res.results||[]).forEach(row=>{
      const m = MEMBERS.find(x=>x.key===row.key);
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${m?m.name:row.key}</td><td>${row.count}</td>`;
      table.appendChild(tr);
    });
  }catch(e){ table.innerHTML='<tr><td colspan=2>결과 로딩 실패</td></tr>'; }
}

async function loadDiary(){
  const wrap=q('#diaryList'); if(!wrap) return;
  try{
    const r = await fetch(window.BACKEND_BASE + '/diary',{credentials:'include'});
    const j = await r.json();
    wrap.innerHTML='';
    (j.items||[]).forEach(d=>{
      const el = document.createElement('div'); el.className='card';
      el.innerHTML = `<div class="head"><strong>${esc(d.title)}</strong><span class="small">${new Date(d.ts).toLocaleString()}</span></div>
        <div class="body">${esc(d.body)}</div>
        <div class="body"><button class="btn ghost" data-del="${d.id}">삭제</button></div>`;
      wrap.appendChild(el);
    });
    if(!wrap.children.length){ wrap.innerHTML='<div class="small">아직 작성된 일기가 없어요。</div>'; }
    qa('[data-del]').forEach(b=> b.addEventListener('click', async ()=>{
      if(!confirm('이 일기를 삭제할까요?')) return;
      const id=b.getAttribute('data-del');
      const r2=await fetch(window.BACKEND_BASE + '/diary/'+id,{method:'DELETE',credentials:'include'});
      const j2=await r2.json(); if(j2.ok) loadDiary(); else alert('삭제 실패');
    }));
  }catch(e){ wrap.innerHTML='<div class="small">일기 로딩 실패</div>'; }
}
function bindDiaryWrite(){
  const t=q('#diaryTitle'), b=q('#diaryBody'), btn=q('#btnDiaryAdd'); if(!btn) return;
  btn.addEventListener('click', async ()=>{
    try{
      const r = await fetch(window.BACKEND_BASE + '/diary', {
        method:'POST',credentials:'include',body:new URLSearchParams({ title:t.value, body:b.value })
      });
      const j=await r.json();
      if(j.ok){ t.value=''; b.value=''; loadDiary(); } else alert('로그인 필요/오류');
    }catch(e){ alert('네트워크 오류'); }
  });
}

async function loadAdmin(){
  const sel1=q('#liveMember'); const sel2=q('#seedMember'); const sel3=q('#pinMember');
  if(!sel1) return;
  [sel1,sel2,sel3].forEach(sel=> MEMBERS.forEach(m=>{
    const o=document.createElement('option'); o.value=m.key; o.textContent=m.name; sel.appendChild(o);
  }));
  q('#btnLiveSave')?.addEventListener('click', async ()=>{
    const key=sel1.value, on=q('#liveOn').checked;
    const r=await fetch(window.BACKEND_BASE + '/live', {method:'POST',credentials:'include',body:new URLSearchParams({key,on:String(on)})});
    const j=await r.json(); alert(j.ok?'저장됨':'실패');
  });
  q('#btnSeedAdd')?.addEventListener('click', async ()=>{
    const r=await fetch(window.BACKEND_BASE + '/gallery/seed', {method:'POST',credentials:'include',body:new URLSearchParams({key:sel2.value,url:q('#seedUrl').value})});
    const j=await r.json(); alert(j.ok?'추가됨':'실패');
  });
  q('#btnPinSet')?.addEventListener('click', async ()=>{
    const r=await fetch(window.BACKEND_BASE + '/gallery/pin', {method:'POST',credentials:'include',body:new URLSearchParams({key:sel3.value,url:q('#pinUrl').value})});
    const j=await r.json(); alert(j.ok?'고정됨':'실패');
  });
  try{
    const r=await fetch(window.BACKEND_BASE + '/confession',{credentials:'include'});
    const j=await r.json();
    const wrap=q('#confessionList'); wrap.innerHTML='';
    (j.items||[]).forEach(c=>{
      const el=document.createElement('div'); el.className='card';
      el.innerHTML=`<div class="head"><strong>익명</strong><span class="small">${new Date(c.ts).toLocaleString()}</span></div>
        <div class="body">${esc(c.body)}</div>
        <div class="body"><button class="btn ghost" data-delc="${c.id}">삭제</button></div>`;
      wrap.appendChild(el);
    });
    qa('[data-delc]').forEach(b=> b.addEventListener('click', async ()=>{
      if(!confirm('삭제할까요?')) return;
      const id=b.getAttribute('data-delc');
      const r2=await fetch(window.BACKEND_BASE + '/confession/'+id,{method:'DELETE',credentials:'include'});
      const j2=await r2.json(); if(j2.ok) loadAdmin();
    }));
  }catch(e){}
}

async function runCorsDiag(){
  const box = document.getElementById('corsDiagBody'); if(!box) return;
  const origin = location.origin;
  let report = [];
  report.push('현재 Origin: ' + origin);
  report.push('백엔드: ' + window.BACKEND_BASE);
  try{
    const r = await fetch(window.BACKEND_BASE + '/session', { credentials:'include' });
    report.push('GET /session 응답: ' + r.status + ' ' + r.statusText);
    const text = await r.text();
    report.push('본문 일부: ' + text.slice(0,120).replace(/\\n/g,' '));
  }catch(e){
    report.push('요청 실패: ' + e);
    report.push('백엔드 CORS 설정 체크리스트:');
    report.push(' - Access-Control-Allow-Origin: ' + origin);
    report.push(' - Access-Control-Allow-Credentials: true');
    report.push(' - Set-Cookie 시 SameSite=None; Secure; Path=/');
    report.push(' - OPTIONS 프리플라이트는 불필요(프론트는 폼 전송 사용)');
  }
  box.innerHTML = '<pre style="white-space:pre-wrap;margin:0">'+report.join('\\n')+'</pre>';
}

(async function(){
  const path = location.pathname.split('/').pop() || 'index.html';
  qa('.tabs .tab').forEach(a=>{ if(a.getAttribute('href').endsWith(path)) a.classList.add('active'); });

  const session = await fetchSession();
  applySessionUI(session);
  initTheme();

  if(q('#membersGrid')) renderMembers(session);
  if(q('#galleryGrid')) loadGallery();
  if(q('#voteList')) loadVote();
  if(q('#diaryList')) loadDiary();
  bindDiaryWrite();
  if(q('#adminGate')) loadAdmin();
  if(q('#liveNowBox')) loadLive();
  runCorsDiag();

  const btnLogout = q('#btnLogout'); btnLogout?.addEventListener('click', logout);
})();
