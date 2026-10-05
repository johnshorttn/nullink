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
  const panel = document.querySelector('.server-status');
  const update = document.getElementById('server-update');
  let timer, controller, lastUpdated;
  function bytes(value) {
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
    return `${value.toLocaleString(undefined, {maximumFractionDigits: 1})} ${units[index]}`;
  }
  function updatedTime() { return new Date(lastUpdated * 1000).toLocaleString(); }
  async function refreshStatus() {
    clearTimeout(timer);
    if (document.hidden || controller) return;
    const request = new AbortController();
    controller = request;
    const timeout = setTimeout(() => request.abort(), 8000);
    try {
      const response = await fetch('/api/portal/status', {
        credentials: 'same-origin', cache: 'no-store', signal: request.signal
      });
      if (response.status === 401) checkSession();
      if (!response.ok) throw new Error('unavailable');
      const data = await response.json();
      if (!Number.isFinite(data.timestamp) || data.timestamp <= 0) throw new Error('timestamp');
      for (const key of ['ram', 'storage']) {
        const metric = data[key];
        if (!metric || ![metric.used_bytes, metric.total_bytes, metric.percent].every(Number.isFinite) ||
            metric.total_bytes <= 0 || metric.used_bytes < 0 || metric.used_bytes > metric.total_bytes ||
            metric.percent < 0 || metric.percent > 100) throw new Error('metrics');
      }
      if (document.hidden || controller !== request) return;
      for (const key of ['ram', 'storage']) {
        const metric = data[key];
        const text = `${bytes(metric.used_bytes)} / ${bytes(metric.total_bytes)} total · ${metric.percent.toFixed(1)}%`;
        document.getElementById(`${key}-value`).textContent = text;
        const bar = document.getElementById(`${key}-progress`);
        bar.value = metric.percent;
        bar.setAttribute('aria-valuetext', text);
      }
      lastUpdated = data.timestamp;
      panel.classList.remove('stale');
      update.textContent = `Last updated ${updatedTime()}`;
    } catch {
      if (document.hidden || controller !== request) return;
      panel.classList.add('stale');
      update.textContent = lastUpdated
        ? `Stale — status unavailable. Last updated ${updatedTime()}. Retrying…`
        : 'Server status unavailable. Retrying…';
      for (const key of ['ram', 'storage']) {
        const bar = document.getElementById(`${key}-progress`);
        if (!lastUpdated) document.getElementById(`${key}-value`).textContent = 'Unavailable';
        bar.setAttribute('aria-valuetext', lastUpdated
          ? `Stale: ${document.getElementById(`${key}-value`).textContent}` : 'Unavailable');
      }
    } finally {
      clearTimeout(timeout);
      if (controller === request) {
        controller = null;
        if (!document.hidden) timer = setTimeout(refreshStatus, 15000);
      }
    }
  }
  function pauseStatus() {
    clearTimeout(timer);
    if (controller) controller.abort();
    controller = null;
  }
  function resumeStatus() {
    if (!document.hidden) { checkSession(); refreshStatus(); }
  }
  window.addEventListener('pageshow', resumeStatus);
  window.addEventListener('pagehide', pauseStatus);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) pauseStatus(); else resumeStatus();
  });
})();
