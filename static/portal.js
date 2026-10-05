(() => {
  async function checkSession() {
    try {
      const response = await fetch('/api/me', {credentials: 'same-origin', cache: 'no-store'});
      if (response.status === 401 || response.status === 403) location.replace('/');
    } catch { /* A transient network failure does not invalidate a session. */ }
  }
  document.getElementById('logout').addEventListener('click', async () => {
    try {
      const response = await fetch('/api/auth/logout', {method: 'POST', credentials: 'same-origin'});
      if (!response.ok) throw new Error('logout');
      location.replace('/');
    } catch {
      document.getElementById('status').textContent = 'Could not log out. Please try again.';
    }
  });
  window.addEventListener('pageshow', checkSession);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) checkSession(); });
  setInterval(checkSession, 30000);
})();
