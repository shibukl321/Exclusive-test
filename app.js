
const BACKEND_BASE = 'https://stelive-shibuki321.io0907op.workers.dev';
const GOOGLE_AUDIENCE = '396083519795-r5j9hfm32ldtb2gumg2de0njk3ak7j0t.apps.googleusercontent.com';

const $ = (q,el=document)=>el.querySelector(q);
function logDiag(msg){ const d = $('#diag'); if(d){ d.textContent += msg + "\n"; }}

async function getSession(){
  try{
    const r = await fetch(BACKEND_BASE+'/session',{credentials:'include'});
    return await r.json();
  }catch(e){ logDiag('세션 실패:'+e); return {}; }
}
window.onGoogleCredential = async (res)=>{
  try{
    const body = new URLSearchParams(); body.set('credential', res.credential);
    const r = await fetch(BACKEND_BASE+'/auth/google',{
      method:'POST',credentials:'include',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body
    });
    if(!r.ok){ const t=await r.text(); alert('로그인 실패:'+t); return; }
    location.reload();
  }catch(e){ alert('네트워크 오류:'+e); }
};
async function setupTopbar(){
  const sess = await getSession();
  if(sess?.user){ $('#btn-logout')?.removeAttribute('hidden'); $('#nav-admin')?.toggleAttribute('hidden', !sess.isAdmin); }
  const btn = $('#btn-logout');
  if(btn){
    btn.addEventListener('click', async ()=>{
      await fetch(BACKEND_BASE+'/auth/logout',{method:'POST',credentials:'include'});
      location.href='./index.html';
    });
  }
}
setupTopbar();

(async function homeInit(){
  if(!$('#live-banner')) return;
  logDiag('Origin:'+location.origin);
  logDiag('Backend:'+BACKEND_BASE);
  try{
    const r = await fetch(BACKEND_BASE+'/live',{credentials:'include'});
    if(r.ok){
      const {live=[]} = await r.json();
      if(live.length){
        $('#live-banner').hidden = false;
        $('#live-names').textContent = live.join(', ');
      }
    }
  }catch(e){ logDiag('라이브 조회 실패:'+e); }
  try{
    const r = await fetch(BACKEND_BASE+'/gallery');
    if(r.ok){
      const {items=[]} = await r.json();
      const el = $('#home-gallery'); items.forEach(it=>{
        const a = document.createElement('a');
        a.href = it.url; a.target='_blank';
        const img = new Image(); img.loading='lazy';
        img.src = (it.url.startsWith('http')? (BACKEND_BASE+'/img?url='+encodeURIComponent(it.url)) : it.url);
        a.appendChild(img); el.appendChild(a);
      })
    }
  }catch(e){ logDiag('갤러리 실패:'+e); }
})();

function cardMember(m){
  return `<div class="card">
    <div class="title">${m.name}</div>
    <div class="note">${m.key}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <a class="ghost" href="${m.stream}" target="_blank">스트리밍</a>
      <a class="ghost" href="${m.covers}" target="_blank">커버곡</a>
      <button class="primary" data-fav="${m.key}">최애 추가</button>
    </div>
  </div>`;
}
async function renderMembers(group){
  if(!window.GROUPS) return;
  const box = document.querySelector('#member-list'); if(!box) return;
  const arr = GROUPS[group] || [];
  box.innerHTML = arr.map(cardMember).join('');
  box.querySelectorAll('button[data-fav]').forEach(btn=>btn.addEventListener('click', async ()=>{
    const key = btn.dataset.fav;
    const body = new URLSearchParams(); body.set('key', key);
    const r = await fetch(BACKEND_BASE+'/prefs/fav',{method:'POST',credentials:'include', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
    if(r.ok) btn.textContent='추가 완료';
    else alert('로그인이 필요합니다.');
  }));
}

(async function setupGallery(){
  const box = document.querySelector('#gallery'); if(!box) return;
  try{
    const r = await fetch(BACKEND_BASE+'/gallery');
    const {items=[]} = await r.json();
    if(!items.length){ box.innerHTML = '<p class="note">아직 등록된 팬아트가 없습니다.</p>'; return; }
    items.forEach(it=>{
      const a = document.createElement('a'); a.href=it.url; a.target='_blank';
      const img = new Image(); img.loading='lazy';
      img.src = BACKEND_BASE+'/img?url='+encodeURIComponent(it.url);
      a.appendChild(img); box.appendChild(a);
    });
  }catch(e){ box.innerHTML='<p>불러오기 실패</p>'; }
})();

async function setupVote(){
  const state = document.querySelector('#vote-state'); const list = document.querySelector('#vote-list'); const btn = document.querySelector('#btn-vote'); if(!btn) return;
  try{
    const r = await fetch(BACKEND_BASE+'/vote/state',{credentials:'include'}); const s = await r.json(); state.textContent = s.message || '';
  }catch(e){ state.textContent='상태 불러오기 실패'; }
  if(window.ALL_MEMBERS){
    list.innerHTML = window.ALL_MEMBERS.map(m=>`<label class="card"><input type="radio" name="vote" value="${m.key}"/> <span class="title">${m.name}</span> <span class="note">${m.key}</span></label>`).join('');
  }
  btn.addEventListener('click', async ()=>{
    const val = (document.querySelector('input[name="vote"]:checked')||{}).value;
    if(!val){ alert('멤버를 선택하세요'); return; }
    const body = new URLSearchParams(); body.set('key', val);
    const r = await fetch(BACKEND_BASE+'/vote',{method:'POST',credentials:'include', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
    const t = await r.text(); if(!r.ok){ alert('실패: '+t); } else { alert('투표 완료'); loadResults(); }
  });
  async function loadResults(){
    const r = await fetch(BACKEND_BASE+'/vote/results'); const {results=[]}= await r.json();
    document.querySelector('#vote-results').innerHTML = results.map(x=>`<div>${x.key}: <b>${x.count}</b></div>`).join('') || '<p class="note">아직 결과가 없습니다.</p>';
  }
  loadResults();
}

async function setupDiaryConfession(){
  const formD = document.querySelector('#form-diary'); const lstD = document.querySelector('#diary-list');
  const formC = document.querySelector('#form-confess'); const lstC = document.querySelector('#conf-list');
  if(formD){
    formD.addEventListener('submit', async (e)=>{
      e.preventDefault();
      const fd = new FormData(formD);
      const r = await fetch(BACKEND_BASE+'/diary',{method:'POST',credentials:'include', body: fd});
      if(!r.ok){ alert('로그인이 필요합니다.'); return; }
      formD.reset(); await loadDiary();
    });
    await loadDiary();
  }
  async function loadDiary(){
    const r = await fetch(BACKEND_BASE+'/diary',{credentials:'include'});
    const {items=[]} = await r.json();
    lstD.innerHTML = items.map(it=>`<li><b>${new Date(it.ts).toLocaleString()}</b> - ${it.title}<br>${escapeHtml(it.body)} <div><button data-del="${it.id}" class="ghost">삭제</button></div></li>`).join('') || '<li class="note">작성한 일기가 없습니다.</li>';
    lstD.querySelectorAll('button[data-del]').forEach(b=>b.addEventListener('click', async ()=>{
      await fetch(BACKEND_BASE+'/diary/'+b.dataset.del,{method:'DELETE',credentials:'include'}); loadDiary();
    }));
  }
  if(formC){
    formC.addEventListener('submit', async (e)=>{
      e.preventDefault();
      const fd = new FormData(formC);
      const r = await fetch(BACKEND_BASE+'/confession',{method:'POST', body: fd});
      if(r.ok){ formC.reset(); loadConf(); } else { alert('전송 실패'); }
    });
    await loadConf();
  }
  async function loadConf(){
    const r = await fetch(BACKEND_BASE+'/confession'); const {items=[]} = await r.json();
    lstC.innerHTML = items.map(it=>`<li><b>${new Date(it.ts).toLocaleString()}</b><br>${escapeHtml(it.message)}</li>`).join('') || '<li class="note">아직 메시지가 없습니다.</li>';
  }
}

async function setupAdmin(){
  const sess = await getSession();
  if(!sess?.isAdmin){ alert('관리자만 접근'); location.href='./index.html'; return; }
  document.querySelector('#form-live')?.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await fetch(BACKEND_BASE+'/live',{method:'POST',credentials:'include', body:fd});
    alert(r.ok?'적용됨':'실패');
  });
  document.querySelector('#form-pin')?.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await fetch(BACKEND_BASE+'/gallery/pin',{method:'POST',credentials:'include', body:fd});
    alert(r.ok?'고정 등록':'실패');
  });
  document.querySelector('#form-seed')?.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await fetch(BACKEND_BASE+'/gallery/seed',{method:'POST',credentials:'include', body:fd});
    alert(r.ok?'랜덤 후보 추가':'실패');
  });

  async function loadAdminConf(){
    const ul = document.querySelector('#admin-conf');
    const r = await fetch(BACKEND_BASE+'/confession'); const {items=[]}= await r.json();
    ul.innerHTML = items.map(it=>`<li data-id="${it.id}"><b>${new Date(it.ts).toLocaleString()}</b><br>${escapeHtml(it.message)}<div><button class="ghost del">삭제</button></div></li>`).join('') || '<li class="note">없음</li>';
    ul.querySelectorAll('.del').forEach(btn=>btn.addEventListener('click', async ()=>{
      const id = btn.closest('li').dataset.id;
      const r = await fetch(BACKEND_BASE+'/confession/'+id,{method:'DELETE',credentials:'include'});
      if(r.ok) loadAdminConf();
    }));
  }
  loadAdminConf();
}

function escapeHtml(s){ return (s||"").replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',\"'\":'&#39;' }[m])); }
