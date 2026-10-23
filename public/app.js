const $ = (id) => document.getElementById(id);

const authView = $('auth-view');
const appView = $('app-view');
const messageBox = $('message');
const loginForm = $('login-form');
const registerForm = $('register-form');

// The JWT lives in an HTTP-only cookie, so this script never sees it.
async function api(path, options = {}) {
  const res = await fetch(path, {
    method: options.method || 'GET',
    headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON response */ }
  if (!res.ok) {
    const err = new Error(data.error || 'Request failed');
    err.status = res.status;
    err.code = data.code;
    throw err;
  }
  return data;
}

function showMessage(text, type = 'error') {
  messageBox.textContent = text;
  messageBox.className = `message ${type}`;
  messageBox.hidden = false;
}
const clearMessage = () => { messageBox.hidden = true; };

function selectTab(which) {
  const isLogin = which === 'login';
  loginForm.hidden = !isLogin;
  registerForm.hidden = isLogin;
  $('tab-login').classList.toggle('active', isLogin);
  $('tab-register').classList.toggle('active', !isLogin);
  $('tab-login').setAttribute('aria-selected', String(isLogin));
  $('tab-register').setAttribute('aria-selected', String(!isLogin));
  clearMessage();
}

function showLoggedIn(user, tokenExpiresAt) {
  authView.hidden = true;
  appView.hidden = false;
  $('welcome').textContent = `Signed in as ${user.name}`;
  $('session-info').textContent = tokenExpiresAt
    ? `${user.email} · session expires ${new Date(tokenExpiresAt).toLocaleTimeString()}`
    : user.email;
  $('protected-output').hidden = true;
}

function showLoggedOut(msg) {
  appView.hidden = true;
  authView.hidden = false;
  selectTab('login');
  if (msg) showMessage(msg, 'ok');
}

async function submitForm(form, path) {
  const button = form.querySelector('button[type=submit]');
  const body = Object.fromEntries(new FormData(form).entries());
  clearMessage();
  button.disabled = true;
  try {
    const { user } = await api(path, { method: 'POST', body });
    form.reset();
    const me = await api('/api/auth/me');
    showLoggedIn(user, me.tokenExpiresAt);
  } catch (err) {
    showMessage(err.message);
  } finally {
    button.disabled = false;
  }
}

loginForm.addEventListener('submit', (e) => { e.preventDefault(); submitForm(loginForm, '/api/auth/login'); });
registerForm.addEventListener('submit', (e) => { e.preventDefault(); submitForm(registerForm, '/api/auth/register'); });
$('tab-login').addEventListener('click', () => selectTab('login'));
$('tab-register').addEventListener('click', () => selectTab('register'));

$('fetch-protected').addEventListener('click', async () => {
  const out = $('protected-output');
  try {
    const data = await api('/api/protected/dashboard');
    out.textContent = JSON.stringify(data, null, 2);
    out.hidden = false;
  } catch (err) {
    if (err.status === 401) return showLoggedOut('Your session expired. Log in again.');
    out.textContent = err.message;
    out.hidden = false;
  }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (_) { /* cookie may already be gone */ }
  showLoggedOut('You have been logged out.');
});

// Restore the session on page load if the cookie is still valid.
(async () => {
  try {
    const me = await api('/api/auth/me');
    showLoggedIn(me.user, me.tokenExpiresAt);
  } catch (_) {
    showLoggedOut();
  }
})();
