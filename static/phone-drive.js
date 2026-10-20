(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const devicesEl = $("devices"), itemsEl = $("items"), crumbsEl = $("crumbs");
  const statusEl = $("browser-status"), pairResult = $("pair-result");
  let selected = null, path = [];
  let screenDeviceId = null, screenSequence = 0, screenObjectUrl = null, screenLastFrameAt = 0;

  let screenEpoch = 0;
  let controlEnabled = false, controlBusy = false, pointer = null;
  function setControl(enabled, message) {
    controlEnabled = enabled;
    document.querySelectorAll("[data-control]").forEach(b => { b.disabled = !enabled || controlBusy; });
    $("screen-frame").style.cursor = enabled ? "crosshair" : "default";
    $("control-status").textContent = message;
  }
  async function sendControl(command, deviceId = screenDeviceId) {
    if (!controlEnabled || controlBusy || !deviceId || deviceId !== screenDeviceId || Date.now() - screenLastFrameAt > 3000) return;
    controlBusy = true;
    try {
      await api("/api/phone/control", {method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({device_id:deviceId,command})});
      if (screenDeviceId === deviceId) $("control-status").textContent = "Control active · tap or drag the image.";
    } catch (error) {
      if (screenDeviceId === deviceId) setControl(false, `Control failed: ${error.message}. Check the phone app.`);
    } finally { controlBusy = false; }
  }
  // Account for object-fit: contain, including any letterboxing in the image element.
  function imagePoint(event) {
    const img = $("screen-frame"), rect = img.getBoundingClientRect();
    if (!img.naturalWidth || !rect.width || !rect.height) return null;
    const scale = Math.min(rect.width / img.naturalWidth, rect.height / img.naturalHeight);
    const width = img.naturalWidth * scale, height = img.naturalHeight * scale;
    const x = (event.clientX - rect.left - (rect.width - width) / 2) / width;
    const y = (event.clientY - rect.top - (rect.height - height) / 2) / height;
    return x >= 0 && x <= 1 && y >= 0 && y <= 1 ? {x,y} : null;
  }
  $("screen-frame").addEventListener("pointerdown", event => {
    if (!controlEnabled || controlBusy || event.button !== 0 || pointer) return;
    const point = imagePoint(event);
    if (!point) return;
    event.preventDefault();
    pointer = {...point, id:event.pointerId, deviceId:screenDeviceId, time:Date.now()};
    event.currentTarget.setPointerCapture(event.pointerId);
  });
  $("screen-frame").addEventListener("pointerup", event => {
    const start = pointer;
    if (!start || start.id !== event.pointerId) return;
    pointer = null;
    const end = imagePoint(event);
    if (!end || start.deviceId !== screenDeviceId) return;
    const distance = Math.hypot(end.x-start.x, end.y-start.y);
    sendControl(distance < .015 ? {action:"tap", x:start.x, y:start.y} :
      {action:"swipe", x:start.x, y:start.y, end_x:end.x, end_y:end.y,
        duration_ms:Math.max(100, Math.min(1000, Date.now()-start.time))}, start.deviceId);
  });
  $("screen-frame").addEventListener("pointercancel", () => { pointer = null; });
  document.querySelectorAll("[data-control]").forEach(button => button.addEventListener("click", () => sendControl({action:button.dataset.control})));

  async function api(url, options = {}) {
    const response = await fetch(url, { credentials: "include", cache: "no-store", ...options });
    const type = response.headers.get("content-type") || "";
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      if (type.includes("json")) {
        const payload = await response.json();
        detail = payload.error || detail;
      }
      throw new Error(detail);
    }
    return type.includes("json") ? response.json() : response;
  }

  function showError(container, error, login = false) {
    const box = document.createElement("div");
    box.className = "empty";
    box.textContent = login ? "Sign in to Nullink in this Chrome profile, then refresh." : error.message;
    container.replaceChildren(box);
  }

  async function refresh() {
    try {
      const data = await api("/api/phone/devices");
      renderDevices(data.devices || []);
      const active = (data.devices || []).find(d => d.id === screenDeviceId);
      setControl(Boolean(active?.control_enabled), active?.control_enabled ? "Control active · tap or drag the image." :
        active?.accessibility_enabled ? "Control off · allow this session in the phone app." : "Control off · enable Nullink Phone Control in Android Accessibility Settings, then allow this session.");
      if (selected && !(data.devices || []).some((d) => d.id === selected.deviceId && d.online && d.sharing && (d.roots || []).some((r) => r.id === selected.rootId))) {
        selected = null; path = []; renderBrowser();
      }
    } catch (error) { setControl(false, "Control unavailable: connection lost."); showError(devicesEl, error, error.message === "unauthorized"); }
  }

  function renderDevices(devices) {
    if (!devices.length) { devicesEl.innerHTML = '<div class="empty">No phone is paired yet.</div>'; return; }
    const fragment = document.createDocumentFragment();
    devices.forEach((device) => {
      const card = document.createElement("div"); card.className = "device";
      const main = document.createElement("div"); main.className = "device-main";
      const name = document.createElement("div"); name.className = "name"; name.textContent = device.name || "Pixel phone";
      const badge = document.createElement("div"); badge.className = "badge";
      badge.textContent = device.screen_active ? "Screen sharing · online" : device.sharing && device.online ? "Sharing folders · online" : device.online ? "Online" : "Offline";
      main.append(name, badge);
      const viewScreen = document.createElement("button"); viewScreen.textContent = "View screen";
      viewScreen.addEventListener("click", () => startScreen(device));
      main.append(viewScreen);
      const roots = document.createElement("div"); roots.className = "roots";
      (device.roots || []).forEach((root) => {
        const btn = document.createElement("button"); btn.className = "root"; btn.textContent = root.name;
        btn.disabled = !device.online || !device.sharing;
        btn.addEventListener("click", () => { selected = {deviceId:device.id,rootId:root.id,name:root.name}; path=[]; browse(); });
        roots.append(btn);
      });
      main.append(roots);
      const revoke = document.createElement("button"); revoke.className = "danger"; revoke.textContent = "Unpair";
      revoke.addEventListener("click", async () => {
        if (!confirm(`Unpair ${device.name || "this phone"}?`)) return;
        try { await api(`/api/phone/devices/${encodeURIComponent(device.id)}`, {method:"DELETE"}); if (selected?.deviceId===device.id) {selected=null;path=[];} await refresh(); }
        catch (error) { statusEl.textContent = error.message; }
      });
      card.append(main,revoke); fragment.append(card);
    });
    devicesEl.replaceChildren(fragment);
  }

  function startScreen(device) {
    screenEpoch++;
    pointer = null; setControl(false, "Checking phone control status…");
    screenDeviceId = device.id;
    refresh();
    screenSequence = 0;
    screenLastFrameAt = 0;
    $("screen-status").textContent = `Waiting for ${device.name || "phone"}. Start mirroring in the phone app and approve Android’s prompt.`;
    $("screen-placeholder").textContent = "Waiting for the phone to send its first frame…";
    $("screen-placeholder").style.display = "block";
    $("screen-frame").style.display = "none";
    $("stop-screen").disabled = false;
    pollScreen();
  }

  function stopScreen() {
    screenEpoch++;
    pointer = null; setControl(false, "Control off · no screen selected.");
    screenDeviceId = null;
    $("stop-screen").disabled = true;
    $("screen-status").textContent = "Screen viewing stopped. Mirroring on the phone may still be active; stop it in the phone app.";
    $("screen-frame").style.display = "none";
    $("screen-placeholder").style.display = "block";
    $("screen-placeholder").textContent = "No screen selected.";
    if (screenObjectUrl) URL.revokeObjectURL(screenObjectUrl);
    screenObjectUrl = null;
  }

  async function pollScreen() {
    const epoch = screenEpoch;
    const deviceId = screenDeviceId;
    if (!deviceId) return;
    try {
      const query = new URLSearchParams({device_id:deviceId, after:String(screenSequence)});
      const response = await fetch(`/api/phone/screen/frame?${query}`, {credentials:"include", cache:"no-store"});
      if (screenDeviceId !== deviceId || screenEpoch !== epoch) return;
      if (response.status === 200) {
        const blob = await response.blob();
        if (screenDeviceId !== deviceId || screenEpoch !== epoch) return;
        const nextUrl = URL.createObjectURL(blob);
        const previousUrl = screenObjectUrl;
        screenObjectUrl = nextUrl;
        screenSequence = Number(response.headers.get("X-Frame-Sequence") || screenSequence);
        screenLastFrameAt = Date.now();
        const frame = $("screen-frame");
        frame.onload = () => { if (previousUrl) URL.revokeObjectURL(previousUrl); };
        frame.src = nextUrl;
        frame.style.display = "block";
        $("screen-placeholder").style.display = "none";
        $("screen-status").textContent = `Live phone screen · frame ${screenSequence}`;
      } else if (response.status === 401) {
        $("screen-status").textContent = "Sign in to Nullink in this browser, then refresh.";
      } else if (response.status !== 204) {
        $("screen-status").textContent = `Screen request failed (${response.status}).`;
      } else if (screenLastFrameAt && Date.now() - screenLastFrameAt > 3000) {
        $("screen-status").textContent = "No new frames. Check that mirroring is active and the phone display is awake.";
      }
    } catch (error) {
      $("screen-status").textContent = error.message || "Screen connection interrupted.";
    }
    if (screenDeviceId === deviceId && screenEpoch === epoch) setTimeout(() => { if (screenEpoch === epoch) pollScreen(); }, 500);
  }

  function renderBrowser(items = null) {
    crumbsEl.replaceChildren();
    if (!selected) { itemsEl.innerHTML = '<div class="empty">No folder selected.</div>'; return; }
    const crumbEntries = [{id:"root",name:selected.name}, ...path];
    crumbEntries.forEach((crumb,index) => {
      const button = document.createElement("button"); button.className="crumb"; button.textContent=crumb.name;
      button.addEventListener("click",()=>{path=path.slice(0,index);browse();}); crumbsEl.append(button);
    });
    if (!items) { itemsEl.innerHTML = '<div class="empty">Loading folder…</div>'; return; }
    if (!items.length) { itemsEl.innerHTML = '<div class="empty">This folder is empty.</div>'; return; }
    const frag=document.createDocumentFragment();
    items.forEach(item=>{
      const row=document.createElement("div");row.className="item";
      const main=document.createElement("div");main.className="item-main";
      const name=document.createElement("div");name.className="name";name.textContent=item.name;
      const meta=document.createElement("div");meta.className="badge";meta.textContent=item.directory?"Folder":`${item.mime||"File"}${item.size?` · ${formatBytes(item.size)}`:""}`;
      main.append(name,meta);row.append(main);
      if(item.directory){const open=document.createElement("button");open.textContent="Open";open.addEventListener("click",()=>{path.push({id:item.id,name:item.name});browse();});row.append(open);}
      else {const download=document.createElement("button");download.className="primary";download.textContent="Download to Chrome";download.addEventListener("click",()=>stage(item,download));row.append(download);}
      frag.append(row);
    });
    itemsEl.replaceChildren(frag);
  }

  async function browse() {
    if (!selected) return;
    const documentId=path.length?path[path.length-1].id:"root";
    renderBrowser(); statusEl.textContent="Requesting a live folder listing from the phone…";
    try {
      const query=new URLSearchParams({device_id:selected.deviceId,root_id:selected.rootId,document_id:documentId});
      const data=await api(`/api/phone/browse?${query}`); renderBrowser(data.items||[]); statusEl.textContent="Folder contents are read-only. File bytes move only when you choose Download.";
    } catch(error){renderBrowser([]);statusEl.textContent=error.message;}
  }

  async function stage(item,button) {
    button.disabled=true;button.textContent="Reading from phone…";statusEl.textContent=`Requesting ${item.name} from the Pixel…`;
    try {
      const data=await api("/api/phone/stage",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({device_id:selected.deviceId,root_id:selected.rootId,document_id:item.id})});
      const response=await api(`/api/phone/staged/${encodeURIComponent(data.file.id)}/download`);
      const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement("a");
      a.href=url;a.download=data.file.name||item.name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
      statusEl.textContent=`Downloaded ${data.file.name||item.name} to this Chrome session. Attach it from Downloads in Messages.`;
    } catch(error){statusEl.textContent=error.message;}
    finally{button.disabled=false;button.textContent="Download to Chrome";}
  }

  function formatBytes(value){if(value<1024)return `${value} B`;if(value<1048576)return `${(value/1024).toFixed(1)} KB`;return `${(value/1048576).toFixed(1)} MB`;}
  $("refresh").addEventListener("click",refresh);
  $("stop-screen").addEventListener("click",stopScreen);
  $("pair-code").addEventListener("click",async()=>{
    pairResult.textContent="Generating…";
    try{const data=await api("/api/phone/pairing-code",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
      pairResult.replaceChildren();const code=document.createElement("span");code.className="code";code.textContent=data.code;pairResult.append(code);
      const timer=document.createElement("span");timer.className="badge";timer.textContent=` · Expires in ${data.expires_in}s`;pairResult.append(timer);
      setTimeout(()=>{timer.textContent=" · Expired";},data.expires_in*1000);
    }catch(error){pairResult.textContent=error.message==="unauthorized"?"Sign in to Nullink first.":error.message;}
  });
  refresh();
  setInterval(refresh, 3000);
})();
