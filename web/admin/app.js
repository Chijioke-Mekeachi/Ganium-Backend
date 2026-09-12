async function postJSON(path, body){
  const res = await fetch(path, {
    method: 'POST', headers: {'Content-Type':'application/json','Accept':'application/json'},
    body: JSON.stringify(body)
  });
  return res.json();
}

const loginForm = document.getElementById('login-form');
const loginMsg = document.getElementById('login-msg');
const statusEl = document.getElementById('status');
const dashboardSection = document.getElementById('dashboard-section');
const dashboardEl = document.getElementById('dashboard');
const usersEl = document.getElementById('users');

let token = null;

loginForm.addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  loginMsg.textContent = '';
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const res = await postJSON('/admin/login', {email, password});
  if(res.token){
    token = res.token;
    statusEl.textContent = 'Signed in as ' + email;
    document.getElementById('login-section').classList.add('hidden');
    dashboardSection.classList.remove('hidden');
    await loadDashboard();
  } else {
    loginMsg.textContent = res.msg || 'login failed';
  }
});

async function loadDashboard(){
  dashboardEl.textContent = 'Loading...';
  const res = await fetch('/api/admin/dashboard', {headers: {Authorization: 'Bearer '+token}});
  if(res.status===200){
    const body = await res.json();
    dashboardEl.textContent = JSON.stringify(body.data, null, 2);
  } else {
    dashboardEl.textContent = 'Failed to load dashboard: '+res.status;
  }

  // load users
  const usersRes = await fetch('/api/admin/users', {headers: {Authorization: 'Bearer '+token}});
  if(usersRes.status===200){
    const body = await usersRes.json();
    usersEl.innerHTML = '';
    (body.data||[]).forEach(u=>{
      const d = document.createElement('div');
      d.className='user';
      d.textContent = (u.email||u._id||'unknown') + ' — ' + (u.role||'') ;
      usersEl.appendChild(d);
    });
  } else {
    usersEl.textContent = 'Failed to load users: '+usersRes.status;
  }
}
