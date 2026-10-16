(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const devicesEl = $("devices"), itemsEl = $("items"), crumbsEl = $("crumbs");
  const statusEl = $("browser-status"), pairResult = $("pair-result");
  let selected = null, path = [];

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
      if (selected && !(data.devices || []).some((d) => d.id === selected.deviceId && d.online && d.sharing && (d.roots || []).some((r) => r.id === selected.rootId))) {
        selected = null; path = []; renderBrowser();
      }
    } catch (error) { showError(devicesEl, error, error.message === "unauthorized"); }
  }

  function renderDevices(devices) {
    if (!devices.length) { devicesEl.innerHTML = '<div class="empty">No phone is paired yet.</div>'; return; }
    const fragment = document.createDocumentFragment();
    devices.forEach((device) => {
      const card = document.createElement("div"); card.className = "device";
      const main = document.createElement("div"); main.className = "device-main";
      const name = document.createElement("div"); name.className = "name"; name.textContent = device.name || "Pixel phone";
      const badge = document.createElement("div"); badge.className = "badge";
      badge.textContent = device.sharing && device.online ? "Sharing folders · online" : device.online ? "Online · sharing stopped" : "Offline";
      main.append(name, badge);
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
  $("pair-code").addEventListener("click",async()=>{
    pairResult.textContent="Generating…";
    try{const data=await api("/api/phone/pairing-code",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
      pairResult.replaceChildren();const code=document.createElement("span");code.className="code";code.textContent=data.code;pairResult.append(code);
      const timer=document.createElement("span");timer.className="badge";timer.textContent=` · Expires in ${data.expires_in}s`;pairResult.append(timer);
      setTimeout(()=>{timer.textContent=" · Expired";},data.expires_in*1000);
    }catch(error){pairResult.textContent=error.message==="unauthorized"?"Sign in to Nullink first.":error.message;}
  });
  refresh();
})();
