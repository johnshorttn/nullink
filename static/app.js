(() => {
  const authView = document.getElementById("auth-view");
  const chatView = document.getElementById("chat-view");
  const pinForm = document.getElementById("pin-form");
  const pinInput = document.getElementById("pin-input");
  const authError = document.getElementById("auth-error");
  const messagesEl = document.getElementById("messages");
  const compose = document.getElementById("compose");
  const composeInput = document.getElementById("compose-input");
  const rosterRoot = document.getElementById("roster-root");
  const logoutBtn = document.getElementById("logout-btn");
  const chatTitle = document.getElementById("chat-title");
  const statusDot = document.getElementById("status-dot");
  const searchInput = document.getElementById("search-input");
  const jumpStart = document.getElementById("jump-start");
  const jumpEnd = document.getElementById("jump-end");

  const tabChat = document.getElementById("tab-chat");
  const tabFiles = document.getElementById("tab-files");
  const tabApps = document.getElementById("tab-apps");
  const tabVault = document.getElementById("tab-vault");
  const chromeTabChat = document.getElementById("chrome-tab-chat");
  const chromeTabFiles = document.getElementById("chrome-tab-files");
  const chromeTabApps = document.getElementById("chrome-tab-apps");
  const chromeTabVault = document.getElementById("chrome-tab-vault");
  const btnNav = document.getElementById("btn-nav");
  const sidebarBackdrop = document.getElementById("sidebar-backdrop");
  /* Fluid Slice 2 — Pixel nav */
  const bottomNav = document.getElementById("nl-bottom-nav");
  const btnRosterClose = document.getElementById("btn-roster-close");
  const rosterSearch = document.getElementById("roster-search");
  const btnChatBack = document.getElementById("btn-chat-back");
  const toolsSheet = document.getElementById("nl-tools-sheet");
  const toolsBackdrop = document.getElementById("nl-tools-backdrop");
  const btnToolsClose = document.getElementById("btn-tools-close");
  const btnSplit = document.getElementById("btn-split");
  const btnSecFiles = document.getElementById("btn-sec-files");
  const btnSecApps = document.getElementById("btn-sec-apps");
  const sidebarEl = document.querySelector(".sidebar");
  const mainEl = document.querySelector(".main");
  const panelChat = document.getElementById("panel-chat");
  const panelFiles = document.getElementById("panel-files");
  const panelApps = document.getElementById("panel-apps");
  const panelVault = document.getElementById("panel-vault");
  const chatSidebar = document.getElementById("chat-sidebar");
  const filesSidebar = document.getElementById("files-sidebar");
  const appsSidebar = document.getElementById("apps-sidebar");
  const vaultSidebar = document.getElementById("vault-sidebar");
  const appsList = document.getElementById("apps-list");
  const appsTitle = document.getElementById("apps-title");
  const appsMeta = document.getElementById("apps-meta");
  const appsEmpty = document.getElementById("apps-empty");
  const appsFrameWrap = document.getElementById("apps-frame-wrap");
  const appsFrame = document.getElementById("apps-frame");
  const btnAppsRefresh = document.getElementById("btn-apps-refresh");
  const btnAppsOpen = document.getElementById("btn-apps-open");
  const labelChips = document.getElementById("label-chips");
  const fileList = document.getElementById("file-list");
  const newLabelForm = document.getElementById("new-label-form");
  const newLabelName = document.getElementById("new-label-name");
  const uploadInput = document.getElementById("upload-input");

  const editor = document.getElementById("editor");
  const gutter = document.getElementById("gutter");
  const editorWrap = document.getElementById("editor-wrap");
  const editorEmpty = document.getElementById("editor-empty");
  const editorFilename = document.getElementById("editor-filename");
  const editorDirty = document.getElementById("editor-dirty");
  const editorMeta = document.getElementById("editor-meta");
  const scratchStatus = document.getElementById("scratch-status");
  const askBox = document.getElementById("ask-box");
  const askMessage = document.getElementById("ask-message");

  const btnSave = document.getElementById("btn-save");
  const btnPreview = document.getElementById("btn-preview");
  const btnAsk = document.getElementById("btn-ask");
  const btnPull = document.getElementById("btn-pull");
  const btnAccept = document.getElementById("btn-accept");
  const btnReject = document.getElementById("btn-reject");
  const btnDiff = document.getElementById("btn-diff");
  const btnDownload = document.getElementById("btn-download");
  const btnNewFile = document.getElementById("btn-new-file");
  const askSend = document.getElementById("ask-send");
  const askCancel = document.getElementById("ask-cancel");
  const diffPanel = document.getElementById("diff-panel");
  const diffView = document.getElementById("diff-view");
  const diffMeta = document.getElementById("diff-meta");
  const diffAccept = document.getElementById("diff-accept");
  const diffReject = document.getElementById("diff-reject");
  const diffAsk = document.getElementById("diff-ask");
  const diffClose = document.getElementById("diff-close");
  const smGoal = document.getElementById("sm-goal");
  const smLastDecision = document.getElementById("sm-last-decision");
  const smBlockers = document.getElementById("sm-blockers");
  const smNotes = document.getElementById("sm-notes");
  const smUpdated = document.getElementById("session-memory-updated");
  const smSaveBtn = document.getElementById("session-memory-save");

  let lastId = 0;
  let activeSession = "morc";
  let pollTimer = null;
  let eventSource = null;
  let sending = false;
  let searchQuery = "";
  let mode = "chat"; // chat | files | apps | vault

  const LAYOUT_KEY = "nullink.layout";
  const CHAT_MIN_KEY = "nullink.chatMinimized";
  const btnChatMin = document.getElementById("btn-chat-minimize");
  const btnChatMinHdr = document.getElementById("btn-chat-minimize-hdr");
  const chatRestoreBar = document.getElementById("chat-restore-bar");
  function readChatMinimized() {
    try { return localStorage.getItem(CHAT_MIN_KEY) === "1"; } catch (_) { return false; }
  }
  function writeChatMinimized(v) {
    try { localStorage.setItem(CHAT_MIN_KEY, v ? "1" : "0"); } catch (_) {}
  }
  let chatMinimized = readChatMinimized();
  function applyChatMinimized() {
    if (mainEl) mainEl.classList.toggle("chat-minimized", !!chatMinimized);
    if (btnChatMin) {
      btnChatMin.setAttribute("aria-pressed", chatMinimized ? "true" : "false");
      btnChatMin.textContent = chatMinimized ? "Show chat" : "Min chat";
      btnChatMin.title = chatMinimized ? "Restore chat panel" : "Minimize chat panel";
    }
    if (btnChatMinHdr) {
      btnChatMinHdr.setAttribute("aria-pressed", chatMinimized ? "true" : "false");
      btnChatMinHdr.title = chatMinimized ? "Chat minimized" : "Minimize chat";
    }
    if (chatRestoreBar) chatRestoreBar.classList.toggle("hidden", !chatMinimized);
  }
  function setChatMinimized(v) {
    chatMinimized = !!v;
    writeChatMinimized(chatMinimized);
    applyChatMinimized();
  }
  function toggleChatMinimized() { setChatMinimized(!chatMinimized); }

  const SPLIT_MIN_WIDTH = 1100;
  const NARROW_MAX_WIDTH = 767; /* Fluid Slice 1 bp-mobile */

  function defaultFluidLayout() {
    return {
      split: false,
      secondary: "files",
      rosterOpen: true,
      workspaceOpen: true, /* preferred at ≥1400; applied only when wide */
      rosterWidth: 260,
      workspaceWidth: 360,
    };
  }

  function readLayout() {
    try {
      const raw = localStorage.getItem(LAYOUT_KEY);
      const base = defaultFluidLayout();
      if (!raw) return base;
      const parsed = JSON.parse(raw);
      const secondary = parsed && (parsed.secondary === "apps" || parsed.secondary === "files")
        ? parsed.secondary
        : "files";
      const rw = Number(parsed && parsed.rosterWidth);
      const ww = Number(parsed && parsed.workspaceWidth);
      return {
        split: !!(parsed && parsed.split),
        secondary,
        rosterOpen: parsed && typeof parsed.rosterOpen === "boolean" ? parsed.rosterOpen : true,
        workspaceOpen: parsed && typeof parsed.workspaceOpen === "boolean" ? parsed.workspaceOpen : true,
        rosterWidth: Number.isFinite(rw) ? Math.min(320, Math.max(220, rw)) : 260,
        workspaceWidth: Number.isFinite(ww) ? Math.min(480, Math.max(280, ww)) : 360,
      };
    } catch {
      return defaultFluidLayout();
    }
  }

  function writeLayout() {
    try {
      localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
    } catch { /* ignore */ }
  }

  let layout = readLayout();

  /* ---- Fluid Slice 4: desktop adaptive panels ---- */
  const BP_TABLET = 768;
  const BP_DESKTOP = 1100;
  const BP_WIDE = 1400;
  const ROSTER_MIN = 220;
  const ROSTER_MAX = 320;
  const WORKSPACE_MIN = 280;
  const WORKSPACE_MAX = 480;
  const CHAT_MIN = 280;

  const btnRosterToggle = document.getElementById("btn-roster-toggle");
  const btnWorkspaceToggle = document.getElementById("btn-workspace-toggle");
  const btnWorkspaceCollapse = document.getElementById("btn-workspace-collapse");
  const rosterRail = document.getElementById("nl-roster-rail");
  const workspaceRail = document.getElementById("nl-workspace-rail");
  const workspaceSlot = document.getElementById("nl-workspace-slot");
  const resizeRoster = document.getElementById("nl-resize-roster");
  const resizeWorkspace = document.getElementById("nl-resize-workspace");

  function viewportW() {
    return window.innerWidth || document.documentElement.clientWidth || 0;
  }
  function isWide3Pane() {
    return viewportW() >= BP_WIDE;
  }
  function isDesktopBand() {
    return viewportW() >= BP_DESKTOP && viewportW() < BP_WIDE;
  }
  function isTabletBand() {
    return viewportW() >= BP_TABLET && viewportW() < BP_DESKTOP;
  }

  function clampRosterW(n) {
    return Math.min(ROSTER_MAX, Math.max(ROSTER_MIN, Math.round(n)));
  }
  function clampWorkspaceW(n) {
    return Math.min(WORKSPACE_MAX, Math.max(WORKSPACE_MIN, Math.round(n)));
  }

  /** Ensure chat keeps ≥ CHAT_MIN when both side panels open */
  function fitPanelWidths() {
    if (!isWide3Pane() || !layout.rosterOpen || !layout.workspaceOpen) return;
    const avail = viewportW();
    let rw = clampRosterW(layout.rosterWidth);
    let ww = clampWorkspaceW(layout.workspaceWidth);
    const chrome = 12; /* handles/borders fudge */
    if (rw + ww + CHAT_MIN + chrome > avail) {
      const overflow = rw + ww + CHAT_MIN + chrome - avail;
      // Shrink workspace first, then roster
      const cutW = Math.min(overflow, ww - WORKSPACE_MIN);
      ww -= cutW;
      const rest = overflow - cutW;
      if (rest > 0) rw = Math.max(ROSTER_MIN, rw - rest);
    }
    layout.rosterWidth = rw;
    layout.workspaceWidth = ww;
  }

  function applyFluidPanels() {
    if (!chatView) return;
    const narrow = isNarrow();
    const wide = isWide3Pane();

    // Widths on shell
    chatView.style.setProperty("--nl-roster-w", clampRosterW(layout.rosterWidth) + "px");
    chatView.style.setProperty("--nl-workspace-w", clampWorkspaceW(layout.workspaceWidth) + "px");

    // Roster collapse (desktop/tablet only)
    const rosterCollapsed = !narrow && !layout.rosterOpen;
    chatView.classList.toggle("nl-roster-collapsed", rosterCollapsed);
    if (rosterRail) {
      rosterRail.classList.toggle("hidden", !rosterCollapsed);
    }
    if (btnRosterToggle) {
      btnRosterToggle.setAttribute("aria-pressed", layout.rosterOpen ? "true" : "false");
      btnRosterToggle.textContent = layout.rosterOpen ? "Roster ‹" : "› Roster";
      btnRosterToggle.title = layout.rosterOpen ? "Collapse roster" : "Expand roster";
    }
    if (resizeRoster) {
      resizeRoster.classList.toggle("hidden", narrow || rosterCollapsed);
    }

    // Workspace 3-pane only at ≥1400; restore preferred open when entering wide
    const wantWorkspace = wide && layout.workspaceOpen;
    const workspaceCollapsed = wide && layout.workspaceOpen === false;
    chatView.classList.toggle("nl-shell--workspace-open", wantWorkspace || workspaceCollapsed);
    chatView.classList.toggle("nl-workspace-collapsed", workspaceCollapsed);

    if (workspaceSlot) {
      const show = wantWorkspace;
      workspaceSlot.hidden = !show;
      workspaceSlot.setAttribute("aria-hidden", show ? "false" : "true");
      if (show) workspaceSlot.removeAttribute("hidden");
      else workspaceSlot.setAttribute("hidden", "");
    }
    if (workspaceRail) {
      workspaceRail.classList.toggle("hidden", !workspaceCollapsed);
    }
    if (resizeWorkspace) {
      resizeWorkspace.classList.toggle("hidden", !wantWorkspace);
    }
    if (btnWorkspaceToggle) {
      const pressed = wide && layout.workspaceOpen;
      btnWorkspaceToggle.setAttribute("aria-pressed", pressed ? "true" : "false");
      btnWorkspaceToggle.textContent = pressed ? "Workspace ›" : "› Workspace";
      btnWorkspaceToggle.title = pressed ? "Collapse workspace" : "Open workspace (wide)";
      btnWorkspaceToggle.style.display = viewportW() >= BP_DESKTOP ? "" : "none";
    }
  }

  function setRosterOpen(open) {
    layout.rosterOpen = !!open;
    writeLayout();
    applyFluidPanels();
  }
  function setWorkspaceOpen(open) {
    layout.workspaceOpen = !!open;
    writeLayout();
    applyFluidPanels();
  }

  function bindResizeHandle(el, which) {
    if (!el) return;
    let startX = 0;
    let startW = 0;
    function onMove(ev) {
      const x = ev.touches ? ev.touches[0].clientX : ev.clientX;
      const dx = x - startX;
      if (which === "roster") {
        layout.rosterWidth = clampRosterW(startW + dx);
      } else {
        layout.workspaceWidth = clampWorkspaceW(startW - dx);
      }
      fitPanelWidths();
      chatView.style.setProperty("--nl-roster-w", layout.rosterWidth + "px");
      chatView.style.setProperty("--nl-workspace-w", layout.workspaceWidth + "px");
    }
    function onUp() {
      chatView.classList.remove("nl-resizing");
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("touchmove", onMove);
      window.removeEventListener("touchend", onUp);
      writeLayout();
      applyFluidPanels();
    }
    function onDown(ev) {
      if (isNarrow()) return;
      ev.preventDefault();
      startX = ev.touches ? ev.touches[0].clientX : ev.clientX;
      startW = which === "roster" ? layout.rosterWidth : layout.workspaceWidth;
      chatView.classList.add("nl-resizing");
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
      window.addEventListener("touchmove", onMove, { passive: false });
      window.addEventListener("touchend", onUp);
    }
    el.addEventListener("pointerdown", onDown);
    el.addEventListener("touchstart", onDown, { passive: false });
  }

  bindResizeHandle(resizeRoster, "roster");
  bindResizeHandle(resizeWorkspace, "workspace");

  if (btnRosterToggle) {
    btnRosterToggle.addEventListener("click", () => setRosterOpen(!layout.rosterOpen));
  }
  if (btnWorkspaceToggle) {
    btnWorkspaceToggle.addEventListener("click", () => {
      if (!isWide3Pane()) {
        // Under 1400: opening workspace means navigate tools via existing modes
        if (typeof openToolTarget === "function") openToolTarget("files");
        else if (typeof setMode === "function") setMode("files");
        return;
      }
      setWorkspaceOpen(!layout.workspaceOpen);
    });
  }
  if (btnWorkspaceCollapse) {
    btnWorkspaceCollapse.addEventListener("click", () => setWorkspaceOpen(false));
  }
  if (rosterRail) {
    rosterRail.addEventListener("click", () => setRosterOpen(true));
  }
  if (workspaceRail) {
    workspaceRail.addEventListener("click", () => setWorkspaceOpen(true));
  }
  // Workspace tiles → reuse Slice 2 openToolTarget
  document.querySelectorAll("#nl-workspace-slot .nl-workspace-tile").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tool = btn.getAttribute("data-tool");
      if (tool && typeof openToolTarget === "function") openToolTarget(tool);
    });
  });

  let _fluidResizeTimer = null;
  let _lastBand = null;
  function fluidBand() {
    const w = viewportW();
    if (w < BP_TABLET) return "mobile";
    if (w < BP_DESKTOP) return "tablet";
    if (w < BP_WIDE) return "desktop";
    return "wide";
  }
  function onFluidResize() {
    clearTimeout(_fluidResizeTimer);
    _fluidResizeTimer = setTimeout(() => {
      const band = fluidBand();
      const prev = _lastBand;
      _lastBand = band;
      // Entering wide: auto-restore 3-pane from saved preference (default open)
      if (band === "wide" && prev && prev !== "wide") {
        fitPanelWidths();
      }
      // Leaving wide: do not permanently flip workspaceOpen false — keep preference
      if (band !== "wide") {
        // ensure shell class cleaned for mid widths
      }
      fitPanelWidths();
      applyFluidPanels();
      if (typeof applyLayout === "function") applyLayout();
    }, 80);
  }
  window.addEventListener("resize", onFluidResize);
  _lastBand = fluidBand();
  fitPanelWidths();
  applyFluidPanels();

  function isWideSplit() {
    return window.matchMedia(`(min-width: ${SPLIT_MIN_WIDTH}px)`).matches;
  }

  function isNarrow() {
    return window.matchMedia(`(max-width: ${NARROW_MAX_WIDTH}px)`).matches;
  }

  function setNavOpen(open) {
    const wasOpen = chatView.classList.contains("nav-open");
    chatView.classList.toggle("nav-open", !!open);
    if (sidebarBackdrop) {
      sidebarBackdrop.classList.toggle("hidden", !open);
      sidebarBackdrop.setAttribute("aria-hidden", open ? "false" : "true");
    }
    if (btnNav) btnNav.setAttribute("aria-expanded", open ? "true" : "false");
    // Restore mode-owned sidebar sections after roster-only drawer close
    if (wasOpen && !open && isNarrow() && typeof applyLayout === "function") {
      applyLayout();
    } else {
      syncBottomNav();
    }
  }

  function closeNav() { setNavOpen(false); }

  /* ---- Fluid Slice 2: Pixel bottom nav + tools sheet ---- */
  let toolsSheetOpen = false;

  function setToolsOpen(open) {
    toolsSheetOpen = !!open;
    if (toolsSheet) {
      toolsSheet.classList.toggle("hidden", !open);
      toolsSheet.setAttribute("aria-hidden", open ? "false" : "true");
    }
    if (toolsBackdrop) {
      toolsBackdrop.classList.toggle("hidden", !open);
      toolsBackdrop.setAttribute("aria-hidden", open ? "false" : "true");
    }
    if (chatView) chatView.classList.toggle("tools-open", !!open);
    syncBottomNav();
  }

  function closeTools() { setToolsOpen(false); }


  // Fluid Slice 3 — session brief collapse (Pixel default collapsed)
  (function initSessionBriefCollapse() {
    const root = document.getElementById("session-memory");
    const toggle = document.getElementById("session-memory-toggle");
    if (!root || !toggle) return;
    const KEY = "nl.sessionBriefExpanded";
    function isNarrow() {
      return window.matchMedia && window.matchMedia("(max-width: 767px)").matches;
    }
    function apply(expanded) {
      root.classList.toggle("is-collapsed", !expanded);
      toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
    }
    let expanded;
    try {
      const saved = localStorage.getItem(KEY);
      if (saved === "1") expanded = true;
      else if (saved === "0") expanded = false;
      else expanded = !isNarrow(); // Pixel default collapsed; desktop open
    } catch (_) {
      expanded = !isNarrow();
    }
    apply(expanded);
    toggle.addEventListener("click", (e) => {
      e.preventDefault();
      expanded = !expanded;
      apply(expanded);
      try { localStorage.setItem(KEY, expanded ? "1" : "0"); } catch (_) {}
    });
    // Also allow clicking head chrome (not Save)
    const head = document.getElementById("session-memory-head");
    if (head) {
      head.addEventListener("click", (e) => {
        if (e.target.closest("#session-memory-save")) return;
        if (e.target.closest("#session-memory-toggle")) return;
        toggle.click();
      });
    }
  })();

  function openRosterDrawer() {
    closeTools();
    // Show roster list in drawer even if another mode owns the sidebar sections
    if (chatSidebar) chatSidebar.classList.remove("hidden");
    if (filesSidebar) filesSidebar.classList.add("hidden");
    if (appsSidebar) appsSidebar.classList.add("hidden");
    if (vaultSidebar) vaultSidebar.classList.add("hidden");
    setNavOpen(true);
    if (rosterSearch && isNarrow()) {
      try { rosterSearch.focus(); } catch { /* ignore */ }
    }
    syncBottomNav();
  }

  function goChatHome(opts) {
    const options = opts || {};
    closeTools();
    closeNav();
    setMode("chat", { keepNav: true, skipFocus: !!options.skipFocus });
    if (!options.skipFocus && composeInput) {
      try { composeInput.focus(); } catch { /* ignore */ }
    }
    syncBottomNav();
  }

  function syncBottomNav() {
    if (!bottomNav) return;
    const items = bottomNav.querySelectorAll(".nl-bottom-nav__item");
    const rosterOpen = !!(chatView && chatView.classList.contains("nav-open"));
    let dest = "chat";
    if (toolsSheetOpen || (isNarrow() && mode !== "chat" && !rosterOpen)) {
      dest = "tools";
    } else if (rosterOpen) {
      dest = "roster";
    } else {
      dest = "chat";
    }
    items.forEach((btn) => {
      const on = btn.getAttribute("data-nav") === dest;
      btn.classList.toggle("is-selected", on);
      if (on) btn.setAttribute("aria-current", "page");
      else btn.removeAttribute("aria-current");
    });
  }

  function filterRoster(query) {
    const q = (query || "").trim().toLowerCase();
    if (!rosterRoot) return;
    rosterRoot.querySelectorAll(".roster-category").forEach((cat) => {
      let any = false;
      cat.querySelectorAll(".roster-bot").forEach((li) => {
        const text = (li.textContent || "").toLowerCase();
        const match = !q || text.includes(q);
        li.classList.toggle("nl-roster-hidden", !match);
        if (match) any = true;
      });
      const empty = cat.querySelector(".roster-empty");
      if (empty) {
        empty.classList.toggle("nl-roster-hidden", !!q);
        if (!q) any = true;
      }
      cat.classList.toggle("nl-roster-hidden", q && !any);
      if (q && any) cat.open = true;
    });
  }

  function openToolTarget(tool) {
    closeTools();
    closeNav();
    if (tool === "files") {
      goMode("files");
    } else if (tool === "apps") {
      goMode("apps");
    } else if (tool === "vault") {
      goMode("vault");
    } else if (tool === "desktop") {
      goMode("apps");
      loadApps().then(() => {
        const desk = (appsCatalog || []).find((a) => a.id === "desktop")
          || (appsCatalog || []).find((a) => /desktop/i.test(a.id || "") || /desktop/i.test(a.title || ""));
        if (desk) openApp(desk.id);
        else if (appsCatalog && appsCatalog[0]) openApp(appsCatalog[0].id);
      });
    } else if (tool === "android") {
      goMode("apps");
      loadApps().then(() => {
        const andr = (appsCatalog || []).find((a) => /android/i.test(a.id || "") || /android/i.test(a.title || ""));
        if (andr) {
          openApp(andr.id);
        } else {
          // Fallback: open /android/ in apps iframe if no catalog entry
          setMode("apps");
          if (appsFrame) {
            appsFrame.src = "/android/";
            if (appsFrameWrap) appsFrameWrap.classList.remove("hidden");
            if (appsEmpty) appsEmpty.classList.add("hidden");
            if (appsTitle) appsTitle.textContent = "Android";
            if (appsMeta) appsMeta.textContent = "/android/";
          }
        }
      });
    } else if (tool === "playground") {
      goMode("files");
      labelFilterSet.clear();
      labelFilterSet.add("chatgpt-playground");
      activeLabelFilter = "chatgpt-playground";
      try { renderLabels(); } catch { /* ignore */ }
      loadFiles();
    }
    syncBottomNav();
  }

  function syncChromeTabs() {
    // When split: highlight secondary on files/apps chrome tabs if those are secondary
    const mark = (el, on) => { if (el) el.classList.toggle("active", !!on); };
    if (layout.split && isWideSplit()) {
      mark(tabChat, true);
      mark(tabFiles, layout.secondary === "files");
      mark(tabApps, layout.secondary === "apps");
      mark(tabVault, false);
      mark(chromeTabChat, true);
      mark(chromeTabFiles, layout.secondary === "files");
      mark(chromeTabApps, layout.secondary === "apps");
      mark(chromeTabVault, false);
    } else {
      mark(tabChat, mode === "chat");
      mark(tabFiles, mode === "files");
      mark(tabApps, mode === "apps");
      mark(tabVault, mode === "vault");
      mark(chromeTabChat, mode === "chat");
      mark(chromeTabFiles, mode === "files");
      mark(chromeTabApps, mode === "apps");
      mark(chromeTabVault, mode === "vault");
    }
    if (btnSplit) {
      const splitLive = !!(layout.split && isWideSplit());
      btnSplit.setAttribute("aria-pressed", layout.split ? "true" : "false");
      btnSplit.classList.toggle("active", !!layout.split);
      btnSplit.textContent = layout.split ? "Split on" : "Split";
      btnSplit.title = isWideSplit()
        ? (layout.split ? "Turn off split view" : "Chat | secondary side-by-side")
        : "Split needs a wide screen";
    }
    if (btnSecFiles) {
      btnSecFiles.setAttribute("aria-pressed", layout.secondary === "files" ? "true" : "false");
      btnSecFiles.title = "Show Files beside Chat (enables Split)";
    }
    if (btnSecApps) {
      btnSecApps.setAttribute("aria-pressed", layout.secondary === "apps" ? "true" : "false");
      btnSecApps.title = "Show Apps beside Chat (enables Split)";
    }
  }

  function applyLayout() {
    const splitLive = !!(layout.split && isWideSplit());
    if (mainEl) mainEl.classList.toggle("split-on", splitLive);
    if (sidebarEl) sidebarEl.classList.toggle("split-secondary", splitLive);

    if (splitLive) {
      panelChat.classList.remove("hidden");
      panelFiles.classList.toggle("hidden", layout.secondary !== "files");
      panelApps.classList.toggle("hidden", layout.secondary !== "apps");
      if (panelVault) panelVault.classList.add("hidden");
      chatSidebar.classList.remove("hidden");
      filesSidebar.classList.toggle("hidden", layout.secondary !== "files");
      appsSidebar.classList.toggle("hidden", layout.secondary !== "apps");
      if (vaultSidebar) vaultSidebar.classList.add("hidden");
      // Keep mode aligned with secondary for loaders / unload logic
      mode = layout.secondary === "apps" ? "apps" : "files";
      // Unload apps iframe if secondary is files
      if (layout.secondary !== "apps" && appsFrame) {
        appsFrame.removeAttribute("src");
        appsFrameWrap.classList.add("hidden");
        appsEmpty.classList.remove("hidden");
      }
    } else {
      if (mainEl) mainEl.classList.remove("split-on");
      panelChat.classList.toggle("hidden", mode !== "chat");
      panelFiles.classList.toggle("hidden", mode !== "files");
      panelApps.classList.toggle("hidden", mode !== "apps");
      if (panelVault) panelVault.classList.toggle("hidden", mode !== "vault");
      chatSidebar.classList.toggle("hidden", mode !== "chat");
      filesSidebar.classList.toggle("hidden", mode !== "files");
      appsSidebar.classList.toggle("hidden", mode !== "apps");
      if (vaultSidebar) vaultSidebar.classList.toggle("hidden", mode !== "vault");
      if (mode !== "apps" && appsFrame) {
        appsFrame.removeAttribute("src");
        appsFrameWrap.classList.add("hidden");
        appsEmpty.classList.remove("hidden");
      }
    }
    syncChromeTabs();
    syncBottomNav();
  }

  let labels = [];
  let files = [];
  let activeLabelFilter = null; // null = all; string id; multi via Set
  let labelFilterSet = new Set();
  let activeFileId = null;
  let editorOpen = false;
  let savedContent = "";
  let scratchId = null;
  let scratchMtime = null;
  let appsCatalog = [];
  let activeAppId = null;
  let presenceTimer = null;
  let inboxOpen = false;
  let inboxItems = [];

  const presenceChip = document.getElementById("presence-chip");
  const presenceLabel = document.getElementById("presence-label");
  const inboxToggle = document.getElementById("inbox-toggle");
  const inboxBadge = document.getElementById("inbox-badge");
  const inboxPanel = document.getElementById("inbox-panel");
  const inboxList = document.getElementById("inbox-list");
  const inboxEmpty = document.getElementById("inbox-empty");
  const inboxRefresh = document.getElementById("inbox-refresh");

  function showAuth() {
    authView.classList.remove("hidden");
    chatView.classList.add("hidden");
    stopRealtime();
  }

  function showApp() {
    authView.classList.add("hidden");
    chatView.classList.remove("hidden");
    loadSessions();
    loadLabels().then(() => loadFiles());
    lastId = 0;
    messagesEl.innerHTML = "";
    fetchMessages(true).then(() => {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    });
    startRealtime();
    startPresencePoll();
    refreshPresenceAndInbox();
    applyLayout();
    if (layout.split && isWideSplit()) {
      if (layout.secondary === "files") loadFiles();
      if (layout.secondary === "apps") {
        loadApps().then(() => { if (activeAppId) openApp(activeAppId); });
      }
    } else {
      setMode(mode, { keepNav: true });
    }
    if (mode === "chat" || (layout.split && isWideSplit())) composeInput.focus();
  }

  function setMode(next, opts) {
    const options = opts || {};
    if (next !== "chat" && next !== "files" && next !== "apps" && next !== "vault") return;

    if (layout.split && isWideSplit()) {
      if (next === "files" || next === "apps") {
        layout.secondary = next;
        writeLayout();
        mode = next;
        applyLayout();
        if (!options.skipLoad) {
          if (next === "files") loadFiles();
          if (next === "apps") {
            loadApps().then(() => { if (activeAppId) openApp(activeAppId); });
          }
        }
      } else {
        // Chat click while split: keep side-by-side, focus compose
        applyLayout();
        if (!options.skipFocus) composeInput.focus();
      }
      if (!options.keepNav) closeNav();
      return;
    }

    mode = next;
    applyLayout();
    if (!options.keepNav) closeNav();
  }

  function goMode(next) {
    if (layout.split && isWideSplit() && next !== "vault") {
      setMode(next);
      return;
    }
    if (next === "files") {
      setMode("files");
      loadFiles();
    } else if (next === "apps") {
      setMode("apps");
      loadApps().then(() => {
        if (activeAppId) openApp(activeAppId);
      });
    } else if (next === "vault") {
      // Vault is full-mode only (not a split secondary)
      if (layout.split) {
        layout.split = false;
        writeLayout();
      }
      setMode("vault");
      loadVaultList();
    } else {
      setMode("chat");
      composeInput.focus();
    }
  }

  tabChat.addEventListener("click", () => goMode("chat"));
  tabFiles.addEventListener("click", () => goMode("files"));
  tabApps.addEventListener("click", () => goMode("apps"));
  if (tabVault) tabVault.addEventListener("click", () => goMode("vault"));
  if (chromeTabChat) chromeTabChat.addEventListener("click", () => goMode("chat"));
  if (chromeTabFiles) chromeTabFiles.addEventListener("click", () => goMode("files"));
  if (chromeTabApps) chromeTabApps.addEventListener("click", () => goMode("apps"));
  if (chromeTabVault) chromeTabVault.addEventListener("click", () => goMode("vault"));

  if (btnNav) {
    btnNav.addEventListener("click", () => {
      const open = !chatView.classList.contains("nav-open");
      setNavOpen(open);
    });
  }
  if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeNav);
  }

  /* Fluid Slice 2 listeners */
  if (bottomNav) {
    bottomNav.addEventListener("click", (e) => {
      const btn = e.target.closest(".nl-bottom-nav__item");
      if (!btn || !bottomNav.contains(btn)) return;
      const dest = btn.getAttribute("data-nav");
      if (dest === "roster") {
        if (chatView.classList.contains("nav-open")) closeNav();
        else openRosterDrawer();
      } else if (dest === "chat") {
        goChatHome();
      } else if (dest === "tools") {
        closeNav();
        if (toolsSheetOpen) closeTools();
        else setToolsOpen(true);
      }
    });
  }
  if (btnRosterClose) btnRosterClose.addEventListener("click", closeNav);
  if (btnChatBack) btnChatBack.addEventListener("click", openRosterDrawer);
  if (btnToolsClose) btnToolsClose.addEventListener("click", closeTools);
  if (toolsBackdrop) toolsBackdrop.addEventListener("click", closeTools);
  if (toolsSheet) {
    toolsSheet.addEventListener("click", (e) => {
      const tile = e.target.closest(".nl-tools-tile");
      if (!tile || !toolsSheet.contains(tile)) return;
      openToolTarget(tile.getAttribute("data-tool"));
    });
  }
  if (rosterSearch) {
    rosterSearch.addEventListener("input", () => filterRoster(rosterSearch.value));
  }
  window.addEventListener("resize", () => {
    if (!isNarrow()) {
      closeTools();
      // desktop: leave nav state alone (sidebar is persistent)
    }
    syncBottomNav();
  });
  if (btnSplit) {
    
  if (btnChatMin) btnChatMin.addEventListener("click", toggleChatMinimized);
  if (btnChatMinHdr) btnChatMinHdr.addEventListener("click", toggleChatMinimized);
  if (chatRestoreBar) chatRestoreBar.addEventListener("click", () => setChatMinimized(false));
  applyChatMinimized();
btnSplit.addEventListener("click", () => {
      layout.split = !layout.split;
      writeLayout();
      if (layout.split) {
        // Ensure secondary panel has content
        if (layout.secondary === "files") loadFiles();
        if (layout.secondary === "apps") {
          loadApps().then(() => { if (activeAppId) openApp(activeAppId); });
        }
      } else {
        mode = "chat";
      }
      applyLayout();
    });
  }
  if (btnSecFiles) {
    btnSecFiles.addEventListener("click", () => {
      if (!layout.split) {
        layout.split = true;
      }
      layout.secondary = "files";
      writeLayout();
      mode = "files";
      applyLayout();
      loadFiles();
    });
  }
  if (btnSecApps) {
    btnSecApps.addEventListener("click", () => {
      if (!layout.split) {
        layout.split = true;
      }
      layout.secondary = "apps";
      writeLayout();
      mode = "apps";
      applyLayout();
      loadApps().then(() => { if (activeAppId) openApp(activeAppId); });
    });
  }

  window.addEventListener("resize", () => {
    applyLayout();
    if (!isNarrow()) closeNav();
  });

  function stopRealtime() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    if (presenceTimer) clearInterval(presenceTimer);
    presenceTimer = null;
    if (eventSource) {
      try { eventSource.close(); } catch (_) {}
      eventSource = null;
    }
  }

  function startRealtime() {
    stopRealtime();
    // Always poll as the reliable path (SSE behind Caddy can stall silently).
    pollTimer = setInterval(() => fetchMessages(false), 1500);
    statusDot.title = "Live (poll)";
    if (typeof EventSource !== "undefined") {
      try { connectSSE(); } catch (_) {}
    }
  }

  function connectSSE() {
    if (eventSource) {
      try { eventSource.close(); } catch (_) {}
      eventSource = null;
    }
    const url =
      `/api/messages/stream?session=${encodeURIComponent(activeSession)}&after=${lastId}`;
    eventSource = new EventSource(url, { withCredentials: true });
    const onPayload = (ev) => {
      try {
        const d = JSON.parse(ev.data);
        ingestMessages(d.messages || [], false);
        statusDot.style.color = "var(--ok)";
        statusDot.title = "Live (SSE+poll)";
      } catch (_) {}
    };
    eventSource.addEventListener("message", onPayload);
    eventSource.onmessage = onPayload; // default-data events too
    eventSource.addEventListener("ping", () => {
      statusDot.style.color = "var(--ok)";
    });
    eventSource.onopen = () => {
      statusDot.style.color = "var(--ok)";
      statusDot.title = "Live (SSE+poll)";
      // Do NOT stop pollTimer — backup stays on.
    };
    eventSource.onerror = () => {
      statusDot.style.color = "var(--warn, #f5a524)";
      statusDot.title = "SSE reconnecting (poll still on)";
      try { eventSource.close(); } catch (_) {}
      eventSource = null;
      if (!pollTimer) {
        pollTimer = setInterval(() => fetchMessages(false), 1500);
      }
      setTimeout(() => {
        if (chatView.classList.contains("hidden")) return;
        try { connectSSE(); } catch (_) {}
      }, 2000);
    };
  }

  // Pull fresh messages when tab becomes visible again
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && !chatView.classList.contains("hidden")) {
      fetchMessages(false);
    }
  });
  window.addEventListener("focus", () => {
    if (!chatView.classList.contains("hidden")) fetchMessages(false);
  });

  function formatWakeTs(ts) {
    if (!ts) return "never";
    try {
      const d = new Date(ts);
      if (Number.isNaN(d.getTime())) return String(ts);
      return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    } catch (_) {
      return String(ts);
    }
  }

  function mapPresenceUi(p) {
    const raw = (p && p.status) || "offline";
    const q = (p && typeof p.queue_depth === "number") ? p.queue_depth : 0;
    const wakeTs = p && p.last_wake_ts;
    let ageMs = Infinity;
    if (wakeTs) {
      const t = Date.parse(wakeTs);
      if (!Number.isNaN(t)) ageMs = Date.now() - t;
    }
    // Spec §12: Online / Working / Idle / Waking / Offline — derive from API without changing it
    let ui = "offline";
    if (raw === "offline") ui = "offline";
    else if (ageMs < 15000 && q === 0) ui = "waking";
    else if (q > 0 || raw === "degraded") ui = "working";
    else if (raw === "online") ui = "online";
    else ui = "idle";
    return { ui, q, wake: formatWakeTs(wakeTs), raw };
  }

  function renderPresence(p) {
    if (!presenceChip || !presenceLabel) return;
    const mapped = mapPresenceUi(p);
    const ui = mapped.ui;
    presenceChip.classList.remove(
      "status-online", "status-degraded", "status-offline",
      "status-working", "status-waking", "status-idle"
    );
    presenceChip.classList.add("status-" + ui);
    const short = {
      online: "Online",
      working: "Working",
      waking: "Waking",
      idle: "Idle",
      offline: "Offline",
    }[ui] || "Offline";
    const narrow = typeof window !== "undefined" && window.matchMedia && window.matchMedia("(max-width: 767px)").matches;
    presenceLabel.textContent = narrow
      ? short
      : `Morc · ${short}` + (mapped.q ? ` · q${mapped.q}` : "");
    presenceChip.title = (p && p.detail)
      ? String(p.detail)
      : `Morc ${short}` + (mapped.wake ? ` · wake ${mapped.wake}` : "") + (mapped.q ? ` · q${mapped.q}` : "");
    if (statusDot) {
      statusDot.dataset.presence = ui;
      statusDot.textContent = ui === "offline" ? "×" : ui === "waking" ? "◌" : ui === "idle" ? "○" : "●";
      statusDot.title = presenceChip.title;
    }
    // Reflect Morc presence onto matching roster row if present
    try {
      document.querySelectorAll(".roster-bot").forEach((el) => {
        el.classList.remove("status-online", "status-working", "status-waking", "status-idle", "status-offline", "status-degraded");
        const id = (el.dataset.id || "").toLowerCase();
        if (id.includes("morc") || id === "chief" || id.includes("chief")) {
          el.classList.add("status-" + ui);
          const st = el.querySelector(".roster-bot__state");
          if (st && !el.classList.contains("active")) st.textContent = short;
          else if (st && el.classList.contains("active")) st.textContent = short;
        }
      });
    } catch (_) { /* ignore */ }
  }

  function kindLabel(kind) {
    const map = {
      "pending.notify": "Notify",
      "pending.ask": "Ask pending",
      "pending.upload": "Upload",
      unanswered_ask: "Ask Morc",
      scratch_accept: "Accept scratch",
      wake_failure: "Wake fail",
      task: "Task",
    };
    return map[kind] || kind || "Item";
  }

  function renderInbox(items) {
    inboxItems = Array.isArray(items) ? items : [];
    const count = inboxItems.length;
    if (inboxBadge) {
      inboxBadge.textContent = String(count);
      inboxBadge.classList.toggle("hidden", false);
      inboxBadge.classList.toggle("zero", count === 0);
    }
    if (!inboxList) return;
    inboxList.innerHTML = "";
    if (inboxEmpty) inboxEmpty.classList.toggle("hidden", count > 0);
    inboxItems.forEach((it) => {
      const li = document.createElement("li");
      li.className = "inbox-item";
      li.dataset.id = it.id || "";
      const title = document.createElement("p");
      title.className = "inbox-item-title";
      title.textContent = it.title || "(no title)";
      const meta = document.createElement("p");
      meta.className = "inbox-item-meta";
      meta.textContent = `${kindLabel(it.kind)} · ${formatWakeTs(it.ts)}`;
      const actions = document.createElement("div");
      actions.className = "inbox-item-actions";

      const openBtn = document.createElement("button");
      openBtn.type = "button";
      openBtn.className = "ghost";
      openBtn.textContent = "Open";
      openBtn.addEventListener("click", () => openInboxItem(it));

      const handledBtn = document.createElement("button");
      handledBtn.type = "button";
      handledBtn.className = "accent-btn";
      handledBtn.textContent = "Handled";
      handledBtn.addEventListener("click", () => mutateInbox(it.id, "handled"));

      const dismissBtn = document.createElement("button");
      dismissBtn.type = "button";
      dismissBtn.className = "ghost";
      dismissBtn.textContent = "Dismiss";
      dismissBtn.addEventListener("click", () => mutateInbox(it.id, "dismiss"));

      actions.appendChild(openBtn);
      if (it.kind === "unanswered_ask" || it.kind === "pending.ask" || it.kind === "scratch_accept") {
        const askBtn = document.createElement("button");
        askBtn.type = "button";
        askBtn.className = "ghost";
        askBtn.textContent = "Ask Morc";
        askBtn.addEventListener("click", () => {
          openInboxItem(it);
          if (typeof btnAsk !== "undefined" && btnAsk && !btnAsk.disabled) {
            setMode("files");
            askBox.classList.remove("hidden");
            askMessage.focus();
          } else {
            setMode("chat");
            activeSession = "morc";
            composeInput.focus();
          }
        });
        actions.appendChild(askBtn);
      }
      actions.appendChild(handledBtn);
      actions.appendChild(dismissBtn);

      li.appendChild(title);
      li.appendChild(meta);
      li.appendChild(actions);
      inboxList.appendChild(li);
    });
  }

  async function openInboxItem(it) {
    const href = String((it && it.href) || "");
    if (href.startsWith("#files/")) {
      const fid = href.slice("#files/".length);
      setMode("files");
      await loadFiles();
      const f = files.find((x) => x.id === fid);
      if (f) openFile(f);
      return;
    }
    if (href.startsWith("#task/")) {
      const tid = href.slice("#task/".length);
      try {
        const r = await fetch(`/api/tasks/${encodeURIComponent(tid)}`, { credentials: "include" });
        if (r.status === 401) return showAuth();
        if (r.ok) {
          const d = await r.json();
          const t = d.task || {};
          showToast(`Task: ${(t.title || tid).slice(0, 80)}`);
          if (t.body) {
            // surface body in compose for quick follow-up
            setMode("chat");
            composeInput.value = `Re: task — ${t.title || ""}\n\n${t.body || ""}`.slice(0, 4000);
            composeInput.focus();
          }
        }
      } catch (_) {}
      return;
    }
    if (href.startsWith("#scratch/")) {
      const sid = href.slice("#scratch/".length);
      setMode("files");
      scratchId = sid;
      try {
        const r = await fetch(`/api/scratch/${encodeURIComponent(sid)}`, { credentials: "include" });
        if (r.ok) {
          const d = await r.json();
          const meta = d.meta || {};
          const content = d.content != null ? d.content : (d.preview || "");
          const name = meta.name || sid;
          showEditor(name, content, meta.file_id || null);
          setScratchStatus(`Opened scratch ${sid}`);
          btnPull.disabled = false;
          btnAccept.disabled = false;
          btnReject.disabled = false;
          btnDiff.disabled = false;
          btnAsk.disabled = false;
          btnPreview.disabled = false;
          loadScratchDiff({ autoShow: true });
        }
      } catch (_) {}
      return;
    }
    setMode("chat");
    activeSession = (it && it.session_id) || "morc";
    if (chatTitle) chatTitle.textContent = "Chief of Staff (Morc)";
    lastId = 0;
    messagesEl.innerHTML = "";
    fetchMessages(true);
  }

  async function mutateInbox(id, action) {
    if (!id) return;
    try {
      const endpoint = action === "handled" ? "/api/inbox/handled" : "/api/inbox/dismiss";
      const r = await fetch(endpoint, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (r.status === 401) return showAuth();
      await refreshPresenceAndInbox();
    } catch (_) {}
  }

  async function refreshPresenceAndInbox() {
    try {
      const [pr, ir] = await Promise.all([
        fetch("/api/presence", { credentials: "include" }),
        fetch("/api/inbox", { credentials: "include" }),
      ]);
      if (pr.status === 401 || ir.status === 401) return showAuth();
      if (pr.ok) renderPresence(await pr.json());
      if (ir.ok) {
        const d = await ir.json();
        renderInbox(d.items || []);
      }
    } catch (_) {
      renderPresence({ status: "offline", last_wake_ts: null, queue_depth: 0, detail: "Presence unreachable" });
    }
  }

  function startPresencePoll() {
    if (presenceTimer) clearInterval(presenceTimer);
    presenceTimer = setInterval(refreshPresenceAndInbox, 8000);
  }

  if (inboxToggle) {
    inboxToggle.addEventListener("click", () => {
      inboxOpen = !inboxOpen;
      inboxPanel.classList.toggle("hidden", !inboxOpen);
      inboxToggle.classList.toggle("open", inboxOpen);
      if (inboxOpen) refreshPresenceAndInbox();
    });
  }
  if (inboxRefresh) {
    inboxRefresh.addEventListener("click", () => refreshPresenceAndInbox());
  }

  async function checkAuth() {
    try {
      const r = await fetch("/api/me", { credentials: "include" });
      const d = await r.json();
      if (d.authenticated) showApp();
      else showAuth();
    } catch {
      showAuth();
      authError.textContent = "Cannot reach bridge server.";
    }
  }

  pinInput.addEventListener("input", () => {
    pinInput.value = pinInput.value.replace(/\D/g, "").slice(0, 6);
    authError.textContent = "";
  });

  pinForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pin = pinInput.value.trim();
    if (pin.length !== 6) {
      authError.textContent = "Enter a 6-digit PIN.";
      return;
    }
    authError.textContent = "";
    try {
      const r = await fetch("/api/auth/verify", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pin }),
      });
      const d = await r.json();
      if (!r.ok) {
        authError.textContent = d.message || "Login failed.";
        return;
      }
      pinInput.value = "";
      showApp();
    } catch {
      authError.textContent = "Network error.";
    }
  });

  logoutBtn.addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    showAuth();
  });

  const ROSTER_COLLAPSE_KEY = "nullink.roster.collapsed";

  function readCollapsedMap() {
    try {
      const raw = localStorage.getItem(ROSTER_COLLAPSE_KEY);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }

  function writeCollapsedMap(map) {
    try {
      localStorage.setItem(ROSTER_COLLAPSE_KEY, JSON.stringify(map));
    } catch { /* ignore */ }
  }

  function selectBot(bot) {
    if (!bot || !bot.id) return;
    activeSession = bot.id;
    chatTitle.textContent = bot.title || bot.id;
    rosterRoot.querySelectorAll(".roster-bot").forEach((el) => {
      el.classList.toggle("active", el.dataset.id === bot.id);
    });
    lastId = 0;
    messagesEl.innerHTML = "";
    fetchMessages(true).then(() => { messagesEl.scrollTop = messagesEl.scrollHeight; });
    startRealtime();
    loadSessionMemory(bot.id);
    if (isNarrow()) {
      closeTools();
      if (mode !== "chat") setMode("chat", { keepNav: true, skipFocus: true });
      closeNav();
      syncBottomNav();
    }
  }

  function renderRoster(categories) {
    const collapsedMap = readCollapsedMap();
    rosterRoot.innerHTML = "";
    (categories || []).forEach((cat) => {
      const details = document.createElement("details");
      details.className = "roster-category";
      details.dataset.catId = cat.id;
      const preferCollapsed = Object.prototype.hasOwnProperty.call(collapsedMap, cat.id)
        ? !!collapsedMap[cat.id]
        : (isNarrow() ? true : !!cat.collapsed);
      details.open = !preferCollapsed;

      const summary = document.createElement("summary");
      summary.className = "roster-cat-header";
      summary.innerHTML = `<span class="roster-chevron" aria-hidden="true"></span><span class="roster-cat-title"></span>`;
      summary.querySelector(".roster-cat-title").textContent = cat.title || cat.id;
      details.appendChild(summary);

      const list = document.createElement("ul");
      list.className = "roster-bots";
      const bots = cat.bots || [];
      if (!bots.length) {
        const empty = document.createElement("li");
        empty.className = "roster-empty";
        empty.textContent = cat.id === "third-party"
          ? "No 3rd-party AIs linked yet"
          : "No bots in this category";
        list.appendChild(empty);
      } else {
        bots.forEach((bot) => {
          const li = document.createElement("li");
          li.className = "roster-bot";
          li.dataset.id = bot.id;
          const dot = document.createElement("span");
          dot.className = "roster-bot__dot";
          dot.setAttribute("aria-hidden", "true");
          const text = document.createElement("span");
          text.className = "roster-bot__text";
          const name = document.createElement("span");
          name.className = "roster-bot__name";
          name.textContent = bot.title || bot.id;
          const state = document.createElement("span");
          state.className = "roster-bot__state";
          const isActive = bot.id === activeSession;
          state.textContent = isActive ? "Active" : (bot.subtitle || bot.state || "Session");
          text.appendChild(name);
          text.appendChild(state);
          li.appendChild(dot);
          li.appendChild(text);
          if (isActive) li.classList.add("active");
          li.addEventListener("click", () => selectBot(bot));
          list.appendChild(li);
        });
      }
      details.appendChild(list);

      details.addEventListener("toggle", () => {
        const map = readCollapsedMap();
        map[cat.id] = !details.open;
        writeCollapsedMap(map);
      });

      rosterRoot.appendChild(details);
    });
  }

  async function loadSessions() {
    try {
      const r = await fetch("/api/sessions", { credentials: "include" });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (d.default_session && !activeSession) {
        activeSession = d.default_session;
      }
      const categories = d.categories || [];
      if (categories.length) {
        renderRoster(categories);
        const flat = d.sessions || [];
        const cur = flat.find((s) => s.id === activeSession) || flat[0];
        if (cur) {
          chatTitle.textContent = cur.title || cur.id;
          if (cur.id !== activeSession) activeSession = cur.id;
        }
        loadSessionMemory(activeSession);
      } else {
        // backward compat: flat sessions only
        renderRoster([{
          id: "sessions",
          title: "Sessions",
          collapsed: false,
          bots: (d.sessions || []).map((s) => ({ id: s.id, title: s.title })),
        }]);
      }
    } catch { /* ignore */ }
  }

  // ---- Labels ----
  async function loadLabels() {
    try {
      const r = await fetch("/api/labels", { credentials: "include" });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      labels = d.labels || [];
      renderLabels();
    } catch { /* ignore */ }
  }

  function renderLabels() {
    labelChips.innerHTML = "";
    const all = document.createElement("button");
    all.type = "button";
    all.className = "chip all" + (labelFilterSet.size === 0 ? " active" : "");
    all.textContent = "All";
    all.addEventListener("click", () => {
      labelFilterSet.clear();
      renderLabels();
      loadFiles();
    });
    labelChips.appendChild(all);

    labels.forEach((l) => {
      const b = document.createElement("button");
      b.type = "button";
      b.dataset.id = l.id;
      b.className = "chip" + (labelFilterSet.has(l.id) ? " active" : "");
      b.title = "Click to filter (multi-select). Right-click to delete.";
      const dot = document.createElement("span");
      dot.className = "dot";
      if (l.color) dot.style.background = l.color;
      b.appendChild(dot);
      b.appendChild(document.createTextNode(l.name));
      b.addEventListener("click", () => {
        if (labelFilterSet.has(l.id)) labelFilterSet.delete(l.id);
        else labelFilterSet.add(l.id);
        renderLabels();
        loadFiles();
      });
      b.addEventListener("contextmenu", async (ev) => {
        ev.preventDefault();
        if (!confirm(`Delete label "${l.name}"?`)) return;
        const r = await fetch(`/api/labels/${encodeURIComponent(l.id)}`, {
          method: "DELETE",
          credentials: "include",
        });
        if (r.ok) {
          labelFilterSet.delete(l.id);
          await loadLabels();
          await loadFiles();
        }
      });
      labelChips.appendChild(b);
    });
  }

  newLabelForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = newLabelName.value.trim();
    if (!name) return;
    const colors = ["#6ea8fe", "#8b7cf7", "#3dd68c", "#f5a524", "#ff6b7a", "#45d1e6"];
    const color = colors[labels.length % colors.length];
    const r = await fetch("/api/labels", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, color }),
    });
    if (r.status === 401) return showAuth();
    if (r.ok) {
      newLabelName.value = "";
      await loadLabels();
    }
  });

  // ---- Files ----
  async function loadFiles() {
    try {
      let url = "/api/files";
      // server filters single label; client intersects multi
      const r = await fetch(url, { credentials: "include" });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      files = d.files || [];
      if (labelFilterSet.size > 0) {
        files = files.filter((f) => {
          const labs = f.labels || [];
          for (const id of labelFilterSet) {
            if (labs.includes(id)) return true;
          }
          return false;
        });
      }
      renderFiles();
    } catch { /* ignore */ }
  }

  function formatSize(n) {
    if (n == null) return "";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  function renderFiles() {
    fileList.innerHTML = "";
    if (!files.length) {
      const li = document.createElement("li");
      li.style.cursor = "default";
      li.textContent = "No files yet";
      fileList.appendChild(li);
      return;
    }
    files
      .slice()
      .sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""))
      .forEach((f) => {
        const li = document.createElement("li");
        li.dataset.id = f.id;
        if (f.id === activeFileId) li.classList.add("active");
        const name = document.createElement("span");
        name.className = "fname";
        name.textContent = f.name;
        const meta = document.createElement("span");
        meta.className = "fmeta";
        meta.textContent = formatSize(f.size);
        li.appendChild(name);
        li.appendChild(meta);
        li.addEventListener("click", () => openFile(f));
        fileList.appendChild(li);
      });
  }

  function isProbablyText(name) {
    const n = String(name || "").toLowerCase();
    return /\.(txt|md|markdown|csv|json|jsonl|ya?ml|toml|ini|cfg|conf|log|html?|css|jsx?|tsx?|py|sh|bash|zsh|sql|xml|rst|ps1|psm1|psd1|vb|vbs|bas|cls|frm|bat|cmd|c|h|cpp|hpp|cs|java|go|rs|rb|php|pl|pm|r|lua|kt|swift|m|mm|vue|svelte|scss|sass|less|tf|proto|gradle|cmake|mk|dockerfile|gitignore|dockerignore|svg)$/.test(n)
      || !n.includes(".");
  }

  async function openFile(f) {
    setMode("files");
    if (isNarrow()) closeNav();
    activeFileId = f.id;
    renderFiles();
    if (!isProbablyText(f.name)) {
      // download binary
      window.open(`/api/files/${encodeURIComponent(f.id)}/download`, "_blank");
      return;
    }
    try {
      const r = await fetch(`/api/files/${encodeURIComponent(f.id)}/content`, { credentials: "include" });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        alert(d.message || d.error || "Cannot open file");
        return;
      }
      showEditor(d.name || f.name, d.content || "", f.id);
    } catch {
      alert("Failed to load file");
    }
  }

  function showEditor(name, content, fileId) {
    editorOpen = true;
    activeFileId = fileId || null;
    savedContent = content;
    editor.value = content;
    editorFilename.textContent = name || "untitled.txt";
    editorEmpty.classList.add("hidden");
    editorWrap.classList.remove("hidden");
    btnSave.disabled = false;
    btnPreview.disabled = false;
    btnAsk.disabled = false;
    btnDownload.disabled = !fileId;
    btnReject.disabled = !scratchId;
    btnDiff.disabled = !scratchId;
    updateDirty();
    updateGutter();
    editorMeta.textContent = `${lineCount(content)} lines`;
    scratchStatus.classList.add("hidden");
    hideDiffPanel();
  }

  function lineCount(text) {
    if (!text) return 0;
    return text.split("\n").length;
  }

  function updateGutter() {
    const n = lineCount(editor.value);
    let s = "";
    for (let i = 1; i <= Math.max(n, 1); i++) s += i + "\n";
    gutter.textContent = s;
    gutter.scrollTop = editor.scrollTop;
  }

  function updateDirty() {
    const dirty = editor.value !== savedContent;
    editorDirty.classList.toggle("hidden", !dirty);
    editorMeta.textContent = `${lineCount(editor.value)} lines` + (dirty ? " · unsaved" : "");
  }

  editor.addEventListener("input", () => {
    updateGutter();
    updateDirty();
  });
  editor.addEventListener("scroll", () => {
    gutter.scrollTop = editor.scrollTop;
  });
  editor.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "s") {
      e.preventDefault();
      saveFile();
    }
    if (e.key === "Tab") {
      e.preventDefault();
      const start = editor.selectionStart;
      const end = editor.selectionEnd;
      const v = editor.value;
      editor.value = v.slice(0, start) + "  " + v.slice(end);
      editor.selectionStart = editor.selectionEnd = start + 2;
      updateGutter();
      updateDirty();
    }
  });

  async function saveFile() {
    if (!editorOpen) return;
    const body = {
      content: editor.value,
      name: editorFilename.textContent,
    };
    if (activeFileId) body.id = activeFileId;
    else {
      const labs = labelFilterSet.size ? [...labelFilterSet] : ["inbox"];
      body.labels = labs;
    }
    const r = await fetch("/api/files/save", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.status === 401) return showAuth();
    const d = await r.json();
    if (!r.ok) {
      alert(d.message || d.error || "Save failed");
      return;
    }
    activeFileId = d.file.id;
    savedContent = editor.value;
    editorFilename.textContent = d.file.name;
    btnDownload.disabled = false;
    updateDirty();
    await loadFiles();
    setScratchStatus("Saved.");
  }

  btnSave.addEventListener("click", saveFile);

  btnNewFile.addEventListener("click", () => {
    const name = prompt("New file name", "untitled.txt");
    if (!name) return;
    scratchId = null;
    showEditor(name, "", null);
    setMode("files");
  });

  btnDownload.addEventListener("click", () => {
    if (!activeFileId) return;
    window.open(`/api/files/${encodeURIComponent(activeFileId)}/download`, "_blank");
  });

  uploadInput.addEventListener("change", async () => {
    const list = uploadInput.files ? Array.from(uploadInput.files) : [];
    uploadInput.value = "";
    if (!list.length) return;
    const fd = new FormData();
    for (const f of list) fd.append("file", f);
    const labs = labelFilterSet.size ? [...labelFilterSet] : ["inbox"];
    fd.append("labels", labs.join(","));
    try {
      setScratchStatus(`Uploading ${list.length} file(s)…`);
      const r = await fetch("/api/files/upload", {
        method: "POST",
        credentials: "include",
        body: fd,
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        alert(d.message || d.error || "Upload failed");
        return;
      }
      setMode("files");
      await loadFiles();
      const saved = d.files || (d.file ? [d.file] : []);
      const n = d.count || saved.length || list.length;
      let msg = `Uploaded ${n} file(s)`;
      if (d.errors && d.errors.length) msg += ` (${d.errors.length} skipped)`;
      setScratchStatus(msg);
      if (saved.length === 1 && isProbablyText(saved[0].name)) openFile(saved[0]);
    } catch {
      alert("Upload network error");
    }
  });

  function setScratchStatus(msg) {
    scratchStatus.textContent = msg;
    scratchStatus.classList.remove("hidden");
  }

  async function doPreview() {
    if (!editorOpen) return null;
    const r = await fetch("/api/files/preview", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: editor.value,
        file_id: activeFileId,
        name: editorFilename.textContent,
        scratch_id: scratchId || undefined,
      }),
    });
    if (r.status === 401) { showAuth(); return null; }
    const d = await r.json();
    if (!r.ok) {
      alert(d.message || d.error || "Preview failed");
      return null;
    }
    scratchId = d.scratch.scratch_id;
    btnPull.disabled = false;
    btnAccept.disabled = false;
    btnReject.disabled = false;
    btnDiff.disabled = false;
    setScratchStatus(`Preview scratch: ${d.scratch.path} (${d.scratch.line_count} lines) — Morc not notified`);
    loadScratchDiff({ autoShow: true });
    return d.scratch;
  }

  btnPreview.addEventListener("click", () => doPreview());

  btnAsk.addEventListener("click", () => {
    askBox.classList.remove("hidden");
    askMessage.focus();
  });
  askCancel.addEventListener("click", () => {
    askBox.classList.add("hidden");
  });
  askSend.addEventListener("click", async () => {
    if (!editorOpen) return;
    // ensure preview first
    const prev = await doPreview();
    if (!prev) return;
    const r = await fetch("/api/files/ask-morc", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scratch_id: scratchId,
        content: editor.value,
        file_id: activeFileId,
        name: editorFilename.textContent,
        message: askMessage.value.trim(),
        labels: labelFilterSet.size ? [...labelFilterSet] : undefined,
      }),
    });
    if (r.status === 401) return showAuth();
    const d = await r.json();
    if (!r.ok) {
      alert(d.message || d.error || "Ask Morc failed");
      return;
    }
    scratchId = d.scratch.scratch_id;
    btnPull.disabled = false;
    btnAccept.disabled = false;
    btnReject.disabled = false;
    btnDiff.disabled = false;
    askBox.classList.add("hidden");
    askMessage.value = "";
    setScratchStatus(`Asked Morc · scratch ${d.scratch.path} (${d.scratch.line_count} lines)`);
    loadScratchDiff({ autoShow: false });
    // jump to chat so John sees the ask
    setMode("chat");
  });

  btnPull.addEventListener("click", async () => {
    if (!scratchId) return;
    const r = await fetch("/api/files/pull-scratch", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scratch_id: scratchId }),
    });
    if (r.status === 401) return showAuth();
    const d = await r.json();
    if (!r.ok) {
      alert(d.message || d.error || "Pull failed");
      return;
    }
    const changed = d.content !== editor.value;
    editor.value = d.content;
    updateGutter();
    updateDirty();
    scratchMtime = d.mtime;
    setScratchStatus(changed
      ? `Pulled updates from scratch/${scratchId}-preview.txt`
      : "Scratch unchanged");
    btnReject.disabled = false;
    btnDiff.disabled = false;
    loadScratchDiff({ autoShow: true });
  });

  function hideDiffPanel() {
    if (diffPanel) diffPanel.classList.add("hidden");
    if (diffView) diffView.textContent = "";
    if (diffMeta) diffMeta.textContent = "";
  }

  function renderDiffText(diff) {
    if (!diffView) return;
    diffView.textContent = "";
    const lines = String(diff || "").split("\n");
    lines.forEach((line, idx) => {
      const span = document.createElement("span");
      span.className = "diff-line";
      if (line.startsWith("+") && !line.startsWith("+++")) span.classList.add("diff-add");
      else if (line.startsWith("-") && !line.startsWith("---")) span.classList.add("diff-del");
      else if (line.startsWith("@@")) span.classList.add("diff-hunk");
      span.textContent = line + (idx < lines.length - 1 ? "\n" : "");
      diffView.appendChild(span);
    });
  }

  async function loadScratchDiff(opts) {
    const autoShow = !!(opts && opts.autoShow);
    if (!scratchId) return null;
    try {
      const r = await fetch(`/api/scratch/${encodeURIComponent(scratchId)}/diff`, { credentials: "include" });
      if (r.status === 401) { showAuth(); return null; }
      const d = await r.json();
      if (!r.ok) {
        if (autoShow) setScratchStatus(d.message || d.error || "Diff unavailable");
        return null;
      }
      const identical = !!d.identical;
      const summary = identical
        ? "No changes vs vault"
        : `Diff vs ${d.base_label || "vault"}`;
      if (diffMeta) diffMeta.textContent = summary;
      renderDiffText(d.diff || "(empty diff)\n");
      if (autoShow && diffPanel) diffPanel.classList.remove("hidden");
      btnDiff.disabled = false;
      btnReject.disabled = false;
      btnAccept.disabled = false;
      return d;
    } catch {
      return null;
    }
  }

  async function doAcceptScratch() {
    if (!scratchId) return;
    const r = await fetch("/api/files/accept-scratch", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scratch_id: scratchId,
        write_through: true,
        file_id: activeFileId || undefined,
        name: editorFilename.textContent,
      }),
    });
    if (r.status === 401) return showAuth();
    const d = await r.json();
    if (!r.ok) {
      alert(d.message || d.error || "Accept failed");
      return;
    }
    editor.value = d.content;
    if (d.file && d.file.id) {
      activeFileId = d.file.id;
      savedContent = d.content;
      btnDownload.disabled = false;
      await loadFiles();
    } else if (activeFileId) {
      savedContent = d.content;
    }
    updateGutter();
    updateDirty();
    setScratchStatus(d.file
      ? `Accepted · wrote through to ${d.file.path || d.file.name}`
      : "Accepted scratch into editor (no linked file — hit Save to persist)");
    hideDiffPanel();
  }

  async function doRejectScratch() {
    if (!scratchId) return;
    if (!confirm("Reject and discard this scratch?")) return;
    const sid = scratchId;
    const r = await fetch("/api/files/reject-scratch", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scratch_id: sid }),
    });
    if (r.status === 401) return showAuth();
    const d = await r.json();
    if (!r.ok) {
      alert(d.message || d.error || "Reject failed");
      return;
    }
    scratchId = null;
    scratchMtime = null;
    btnPull.disabled = true;
    btnAccept.disabled = true;
    btnReject.disabled = true;
    btnDiff.disabled = true;
    hideDiffPanel();
    setScratchStatus(`Rejected · discarded scratch ${sid}`);
  }

  btnAccept.addEventListener("click", () => doAcceptScratch());
  if (btnReject) btnReject.addEventListener("click", () => doRejectScratch());
  if (btnDiff) btnDiff.addEventListener("click", async () => {
    const d = await loadScratchDiff({ autoShow: true });
    if (d && diffPanel) diffPanel.classList.remove("hidden");
  });
  if (diffAccept) diffAccept.addEventListener("click", () => doAcceptScratch());
  if (diffReject) diffReject.addEventListener("click", () => doRejectScratch());
  if (diffAsk) diffAsk.addEventListener("click", () => {
    askBox.classList.remove("hidden");
    askMessage.focus();
  });
  if (diffClose) diffClose.addEventListener("click", () => hideDiffPanel());

  // ---- Session memory ----
  function formatSmTs(ts) {
    if (!ts) return "";
    try {
      const d = new Date(ts);
      if (Number.isNaN(d.getTime())) return String(ts);
      return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    } catch {
      return String(ts);
    }
  }

  function paintSessionMemory(mem) {
    const m = mem || {};
    if (smGoal) smGoal.value = m.goal || "";
    if (smLastDecision) smLastDecision.value = m.last_decision || "";
    if (smBlockers) smBlockers.value = m.blockers || "";
    if (smNotes) smNotes.value = m.notes || "";
    if (smUpdated) smUpdated.textContent = m.updated_at ? `Updated ${formatSmTs(m.updated_at)}` : "Not set";
  }

  async function loadSessionMemory(botId) {
    const id = botId || activeSession || "morc";
    try {
      const r = await fetch(`/api/session-memory/${encodeURIComponent(id)}`, { credentials: "include" });
      if (r.status === 401) return showAuth();
      if (!r.ok) {
        paintSessionMemory({});
        return;
      }
      const d = await r.json();
      paintSessionMemory(d.memory || {});
    } catch {
      paintSessionMemory({});
    }
  }

  async function saveSessionMemory() {
    const id = activeSession || "morc";
    const body = {
      goal: smGoal ? smGoal.value : "",
      last_decision: smLastDecision ? smLastDecision.value : "",
      blockers: smBlockers ? smBlockers.value : "",
      notes: smNotes ? smNotes.value : "",
    };
    try {
      const r = await fetch(`/api/session-memory/${encodeURIComponent(id)}`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        alert(d.message || d.error || "Save brief failed");
        return;
      }
      paintSessionMemory(d.memory || body);
    } catch {
      alert("Network error saving brief");
    }
  }

  if (smSaveBtn) smSaveBtn.addEventListener("click", () => saveSessionMemory());

  // ---- Apps ----
  async function loadApps() {
    try {
      const res = await fetch("/api/apps", { credentials: "include" });
      if (!res.ok) throw new Error("apps " + res.status);
      const data = await res.json();
      appsCatalog = data.apps || [];
      renderAppsList();
    } catch (e) {
      const detail = (e && e.message) ? String(e.message) : "unknown";
      if (appsList) {
        appsList.innerHTML = "<li class=\"muted-meta\">Failed to load apps (" + detail + ")</li>";
      }
      console.error("loadApps", e);
    }
  }

  function renderAppsList() {
    appsList.innerHTML = "";
    if (!appsCatalog.length) {
      appsList.innerHTML = "<li class=\"muted-meta\">No apps configured</li>";
      return;
    }
    for (const app of appsCatalog) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.disabled = !app.enabled || !app.embed_url;
      btn.classList.toggle("active", app.id === activeAppId);
      btn.innerHTML = `<span class="app-title"></span><span class="app-desc"></span>`;
      btn.querySelector(".app-title").textContent = app.title || app.id;
      let desc = app.description || "";
      if (!app.enabled) desc = (desc ? desc + " — " : "") + "disabled";
      btn.querySelector(".app-desc").textContent = desc;
      btn.addEventListener("click", () => openApp(app.id));
      li.appendChild(btn);
      appsList.appendChild(li);
    }
  }

  function openApp(id) {
    const app = appsCatalog.find((a) => a.id === id);
    activeAppId = id;
    renderAppsList();
    if (!app || !app.enabled || !app.embed_url) {
      appsTitle.textContent = "Apps";
      appsMeta.textContent = "";
      appsFrame.removeAttribute("src");
      appsFrameWrap.classList.add("hidden");
      appsEmpty.classList.remove("hidden");
      btnAppsOpen.disabled = true;
      return;
    }
    appsTitle.textContent = app.title || app.id;
    appsMeta.textContent = app.kind === "path" ? app.embed_url : "proxied " + app.embed_url;
    appsEmpty.classList.add("hidden");
    appsFrameWrap.classList.remove("hidden");
    btnAppsOpen.disabled = false;

    // Desktop / Gmail-via-Desktop: after Nullink OTP session, auto-login Guacamole
    const wantsDesktop =
      app.id === "desktop" ||
      app.id === "gmail" ||
      (app.embed_url || "").startsWith("/desktop");
    if (wantsDesktop) {
      appsMeta.textContent = "Signing into desktop…";
      fetch("/api/desktop/launch", { credentials: "include" })
        .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
        .then(({ ok, d }) => {
          if (!ok || !d.embedUrl) {
            appsMeta.textContent = "Desktop auto-login failed — falling back";
            appsFrame.src = app.embed_url;
            return;
          }
          appsMeta.textContent = "Desktop (PIN session) · " + (d.username || "desk");
          appsFrame.src = d.embedUrl;
        })
        .catch(() => {
          appsMeta.textContent = "Desktop auto-login error — falling back";
          appsFrame.src = app.embed_url;
        });
      return;
    }

    if (appsFrame.getAttribute("src") !== app.embed_url) {
      appsFrame.src = app.embed_url;
    }
  }


  btnAppsRefresh.addEventListener("click", () => {
    loadApps().then(() => {
      if (activeAppId) {
        const app = appsCatalog.find((a) => a.id === activeAppId);
        if (app && app.embed_url) {
          appsFrame.src = app.embed_url;
        }
      }
    });
  });
  btnAppsOpen.addEventListener("click", () => {
    const app = appsCatalog.find((a) => a.id === activeAppId);
    if (app && app.embed_url) window.open(app.embed_url, "_blank", "noopener");
  });

  // ---- Chat helpers (existing) ----
  function escapeHtml(s) {
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatTs(ts) {
    if (!ts) return "";
    try {
      const d = new Date(ts);
      if (isNaN(d)) return ts;
      return d.toLocaleString(undefined, {
        month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
      });
    } catch {
      return ts;
    }
  }

  function highlightText(text, q) {
    const safe = escapeHtml(text || "");
    if (!q) return safe;
    const esc = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    try {
      return safe.replace(new RegExp(`(${esc})`, "gi"), "<mark>$1</mark>");
    } catch {
      return safe;
    }
  }

  function applySearchFilter() {
    const q = searchQuery.trim().toLowerCase();
    [...messagesEl.querySelectorAll(".bubble-row")].forEach((row) => {
      const text = (row.dataset.text || "").toLowerCase();
      const match = !q || text.includes(q);
      row.classList.toggle("search-hide", !match);
      const bubble = row.querySelector(".bubble");
      if (bubble) {
        bubble.innerHTML = highlightText(row.dataset.text || "", q ? searchQuery.trim() : "");
      }
    });
  }

  function appendBubble(msg) {
    if (messagesEl.querySelector(`.bubble-row[data-id="${msg.id}"]`)) return;
    const row = document.createElement("div");
    row.className = `bubble-row ${msg.role === "user" ? "user" : "assistant"}`;
    row.dataset.id = msg.id;
    row.dataset.text = msg.text || "";
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.innerHTML = highlightText(msg.text || "", searchQuery.trim());
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = formatTs(msg.ts);
    const wrap = document.createElement("div");
    wrap.appendChild(bubble);
    wrap.appendChild(meta);
    row.appendChild(wrap);
    messagesEl.appendChild(row);
    if (searchQuery.trim()) {
      const match = (msg.text || "").toLowerCase().includes(searchQuery.trim().toLowerCase());
      row.classList.toggle("search-hide", !match);
    }
  }

  function ingestMessages(msgs, scrollForce) {
    if (!msgs.length) return;
    const nearBottom =
      messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 80;
    msgs.forEach((m) => {
      if (m.id > lastId) lastId = m.id;
      appendBubble(m);
    });
    if (scrollForce || nearBottom) {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }
  }

  async function fetchMessages(scrollForce) {
    try {
      const r = await fetch(
        `/api/messages?session=${encodeURIComponent(activeSession)}&after=${lastId}`,
        { credentials: "include" }
      );
      if (r.status === 401) return showAuth();
      statusDot.style.color = "var(--ok)";
      const d = await r.json();
      ingestMessages(d.messages || [], scrollForce);
    } catch {
      statusDot.style.color = "var(--danger)";
    }
  }

  searchInput.addEventListener("input", () => {
    searchQuery = searchInput.value;
    applySearchFilter();
  });

  jumpStart.addEventListener("click", () => {
    messagesEl.scrollTop = 0;
  });
  jumpEnd.addEventListener("click", () => {
    messagesEl.scrollTop = messagesEl.scrollHeight;
  });

  compose.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (sending) return;
    const text = composeInput.value.trim();
    if (!text) return;
    sending = true;
    composeInput.value = "";
    autoResize();
    try {
      const r = await fetch("/api/messages", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, session_id: activeSession }),
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (r.ok && d.message) {
        if (d.message.id > lastId) lastId = d.message.id;
        appendBubble(d.message);
        messagesEl.scrollTop = messagesEl.scrollHeight;
      }
    } catch {
      statusDot.style.color = "var(--danger)";
    } finally {
      sending = false;
      composeInput.focus();
    }
  });

  function autoResize() {
    composeInput.style.height = "auto";
    composeInput.style.height = Math.min(composeInput.scrollHeight, 160) + "px";
  }
  composeInput.addEventListener("input", autoResize);
  composeInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      compose.requestSubmit();
    }
  });


  // ---- Slice D: toast + selection toolbar + vault ----
  const selToolbar = document.getElementById("sel-toolbar");
  const selMakeTask = document.getElementById("sel-make-task");
  const selAddLabel = document.getElementById("sel-add-label");
  const selAskMorc = document.getElementById("sel-ask-morc");
  const selLabelPicker = document.getElementById("sel-label-picker");
  const selLabelList = document.getElementById("sel-label-list");
  const selLabelCancel = document.getElementById("sel-label-cancel");
  const toastEl = document.getElementById("toast");

  const vaultSearch = document.getElementById("vault-search");
  const vaultList = document.getElementById("vault-list");
  const vaultEmpty = document.getElementById("vault-empty");
  const vaultNewBtn = document.getElementById("vault-new-btn");
  const vaultNewBtnMain = document.getElementById("vault-new-btn-main");
  const vaultSaveBtn = document.getElementById("vault-save-btn");
  const vaultDeleteBtn = document.getElementById("vault-delete-btn");
  const vaultEditorEmpty = document.getElementById("vault-editor-empty");
  const vaultEditorWrap = document.getElementById("vault-editor-wrap");
  const vaultTitleInput = document.getElementById("vault-title-input");
  const vaultTagsInput = document.getElementById("vault-tags-input");
  const vaultBodyInput = document.getElementById("vault-body-input");
  const vaultMeta = document.getElementById("vault-meta");

  let selText = "";
  let selSource = "chat"; // chat | editor
  let toastTimer = null;
  let vaultItems = [];
  let activeVaultId = null;
  let vaultDirty = false;

  function showToast(msg, ms) {
    if (!toastEl) {
      try { console.log("[nullink]", msg); } catch (_) {}
      return;
    }
    toastEl.textContent = String(msg || "");
    toastEl.classList.remove("hidden");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.add("hidden"), ms || 2800);
  }

  function hideSelToolbar() {
    if (selToolbar) selToolbar.classList.add("hidden");
  }

  function placeSelToolbar(x, y) {
    if (!selToolbar) return;
    selToolbar.classList.remove("hidden");
    const pad = 8;
    const rect = selToolbar.getBoundingClientRect();
    let left = x;
    let top = y - rect.height - 10;
    if (top < pad) top = y + 12;
    if (left + rect.width > window.innerWidth - pad) left = window.innerWidth - rect.width - pad;
    if (left < pad) left = pad;
    selToolbar.style.left = `${Math.round(left)}px`;
    selToolbar.style.top = `${Math.round(top)}px`;
  }

  function getEditorSelection() {
    if (!editor) return "";
    const a = editor.selectionStart;
    const b = editor.selectionEnd;
    if (a == null || b == null || a === b) return "";
    return String(editor.value || "").slice(Math.min(a, b), Math.max(a, b));
  }

  function getChatSelection() {
    const sel = window.getSelection && window.getSelection();
    if (!sel || sel.isCollapsed || !sel.rangeCount) return "";
    const text = String(sel.toString() || "").trim();
    if (!text) return "";
    // only if selection is inside messages
    try {
      const node = sel.anchorNode;
      if (!messagesEl || !messagesEl.contains(node)) return "";
    } catch (_) {
      return "";
    }
    return text;
  }

  function refreshSelectionToolbar(ev) {
    // Don't steal focus from toolbar clicks
    if (ev && selToolbar && selToolbar.contains(ev.target)) return;
    if (ev && selLabelPicker && !selLabelPicker.classList.contains("hidden") && selLabelPicker.contains(ev.target)) return;

    let text = "";
    let source = "chat";
    const edSel = getEditorSelection();
    if (edSel && edSel.trim() && document.activeElement === editor) {
      text = edSel.trim();
      source = "editor";
    } else {
      const chatSel = getChatSelection();
      if (chatSel) {
        text = chatSel;
        source = "chat";
      } else if (edSel && edSel.trim()) {
        text = edSel.trim();
        source = "editor";
      }
    }
    if (!text || text.length < 1) {
      selText = "";
      hideSelToolbar();
      return;
    }
    selText = text.slice(0, 8000);
    selSource = source;
    let x = (ev && ev.clientX) || window.innerWidth / 2;
    let y = (ev && ev.clientY) || 120;
    if (source === "chat") {
      try {
        const sel = window.getSelection();
        if (sel && sel.rangeCount) {
          const r = sel.getRangeAt(0).getBoundingClientRect();
          if (r && (r.width || r.height)) {
            x = r.left + r.width / 2;
            y = r.top;
          }
        }
      } catch (_) {}
    }
    placeSelToolbar(x, y);
  }

  document.addEventListener("mouseup", (ev) => {
    setTimeout(() => refreshSelectionToolbar(ev), 10);
  });
  document.addEventListener("keyup", (ev) => {
    if (ev.key === "Escape") {
      hideSelToolbar();
      if (selLabelPicker) selLabelPicker.classList.add("hidden");
      return;
    }
    setTimeout(() => refreshSelectionToolbar(ev), 10);
  });
  document.addEventListener("scroll", () => hideSelToolbar(), true);
  document.addEventListener("mousedown", (ev) => {
    if (selToolbar && !selToolbar.contains(ev.target) && !(selLabelPicker && selLabelPicker.contains(ev.target))) {
      // delay hide so button click can fire
      setTimeout(() => {
        if (!selText) hideSelToolbar();
      }, 150);
    }
  });

  async function makeTaskFromSelection(labelId) {
    const text = (selText || "").trim();
    if (!text) return showToast("Nothing selected");
    const title = text.split("\n").map((l) => l.trim()).find(Boolean) || "Task";
    try {
      const r = await fetch("/api/tasks", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: title.slice(0, 120),
          body: text,
          label_id: labelId || undefined,
          source: selSource === "editor" ? "editor" : "chat",
        }),
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        showToast(d.message || d.error || "Task failed");
        return;
      }
      hideSelToolbar();
      showToast("Task created — in Inbox");
      refreshPresenceAndInbox();
    } catch (_) {
      showToast("Network error");
    }
  }

  function openLabelPicker() {
    if (!selLabelPicker || !selLabelList) return;
    selLabelList.innerHTML = "";
    (labels || []).forEach((l) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      const dot = document.createElement("span");
      dot.className = "dot";
      if (l.color) dot.style.background = l.color;
      b.appendChild(dot);
      b.appendChild(document.createTextNode(l.name));
      b.addEventListener("click", () => attachSelectionLabel(l.id));
      selLabelList.appendChild(b);
    });
    if (!(labels || []).length) {
      const p = document.createElement("p");
      p.className = "hint";
      p.textContent = "No labels yet — create one in the sidebar.";
      selLabelList.appendChild(p);
    }
    selLabelPicker.classList.remove("hidden");
  }

  async function attachSelectionLabel(labelId) {
    const text = (selText || "").trim();
    if (!text) return;
    if (selLabelPicker) selLabelPicker.classList.add("hidden");
    try {
      const r = await fetch("/api/selection/label", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          label_id: labelId,
          source: selSource,
          also_task: false,
        }),
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        showToast(d.message || d.error || "Label attach failed");
        return;
      }
      hideSelToolbar();
      showToast(`Labeled paste → ${labelId}`);
      if (typeof loadFiles === "function") loadFiles();
    } catch (_) {
      showToast("Network error");
    }
  }

  async function askMorcFromSelection() {
    const text = (selText || "").trim();
    if (!text) return showToast("Nothing selected");
    const note = window.prompt("Note for Morc (optional):", "Please review this selection") || "";
    try {
      const r = await fetch("/api/files/ask-morc", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: text,
          name: selSource === "editor" ? `selection-${(editorFilename && editorFilename.textContent) || "editor"}.txt` : "selection-chat.txt",
          message: note,
          file_id: selSource === "editor" ? (activeFileId || undefined) : undefined,
        }),
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        showToast(d.message || d.error || "Ask Morc failed");
        return;
      }
      hideSelToolbar();
      const sid = (d.scratch && (d.scratch.scratch_id || d.scratch.id)) || d.scratch_id;
      if (sid) scratchId = sid;
      showToast("Asked Morc with selection");
      refreshPresenceAndInbox();
      setMode("chat");
    } catch (_) {
      showToast("Network error");
    }
  }

  if (selMakeTask) selMakeTask.addEventListener("click", (e) => { e.preventDefault(); makeTaskFromSelection(); });
  if (selAddLabel) selAddLabel.addEventListener("click", (e) => { e.preventDefault(); openLabelPicker(); });
  if (selAskMorc) selAskMorc.addEventListener("click", (e) => { e.preventDefault(); askMorcFromSelection(); });
  if (selLabelCancel) selLabelCancel.addEventListener("click", () => selLabelPicker && selLabelPicker.classList.add("hidden"));
  if (selLabelPicker) selLabelPicker.addEventListener("click", (e) => {
    if (e.target === selLabelPicker) selLabelPicker.classList.add("hidden");
  });

  function parseTags(raw) {
    return String(raw || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .slice(0, 24);
  }

  function markVaultDirty() {
    vaultDirty = true;
    if (vaultSaveBtn) vaultSaveBtn.disabled = false;
  }

  function showVaultEditor(item) {
    if (!vaultEditorWrap || !vaultEditorEmpty) return;
    if (!item) {
      vaultEditorWrap.classList.add("hidden");
      vaultEditorEmpty.classList.remove("hidden");
      if (vaultSaveBtn) vaultSaveBtn.disabled = true;
      if (vaultDeleteBtn) vaultDeleteBtn.disabled = true;
      if (vaultMeta) vaultMeta.textContent = "";
      return;
    }
    vaultEditorEmpty.classList.add("hidden");
    vaultEditorWrap.classList.remove("hidden");
    if (vaultTitleInput) vaultTitleInput.value = item.title || "";
    if (vaultTagsInput) vaultTagsInput.value = (item.tags || []).join(", ");
    if (vaultBodyInput) vaultBodyInput.value = item.body || "";
    if (vaultSaveBtn) vaultSaveBtn.disabled = true;
    if (vaultDeleteBtn) vaultDeleteBtn.disabled = !item.id;
    vaultDirty = false;
    if (vaultMeta) {
      vaultMeta.textContent = item.updated_at ? `Updated ${item.updated_at}` : (item.id ? `id ${item.id}` : "New");
    }
  }

  function renderVaultList(items) {
    vaultItems = Array.isArray(items) ? items : [];
    if (!vaultList) return;
    vaultList.innerHTML = "";
    if (vaultEmpty) vaultEmpty.classList.toggle("hidden", vaultItems.length > 0);
    vaultItems.forEach((it) => {
      const li = document.createElement("li");
      li.dataset.id = it.id;
      if (it.id === activeVaultId) li.classList.add("active");
      const title = document.createElement("div");
      title.className = "vault-item-title";
      title.textContent = it.title || "(untitled)";
      const tags = document.createElement("div");
      tags.className = "vault-item-tags";
      tags.textContent = (it.tags || []).join(", ") || "no tags";
      li.appendChild(title);
      li.appendChild(tags);
      li.addEventListener("click", () => openVaultItem(it.id));
      vaultList.appendChild(li);
    });
  }

  async function loadVaultList(q) {
    try {
      const query = q != null ? q : (vaultSearch ? vaultSearch.value.trim() : "");
      const url = query ? `/api/vault?q=${encodeURIComponent(query)}` : "/api/vault";
      const r = await fetch(url, { credentials: "include" });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      renderVaultList(d.items || []);
    } catch (_) {}
  }

  async function openVaultItem(vid) {
    if (!vid) return;
    try {
      const r = await fetch(`/api/vault/${encodeURIComponent(vid)}`, { credentials: "include" });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        showToast(d.error || "Not found");
        return;
      }
      activeVaultId = (d.item && d.item.id) || vid;
      showVaultEditor(d.item);
      renderVaultList(vaultItems);
    } catch (_) {
      showToast("Network error");
    }
  }

  function newVaultSnippet() {
    activeVaultId = null;
    showVaultEditor({ title: "", body: "", tags: [] });
    if (vaultTitleInput) vaultTitleInput.focus();
    if (vaultSaveBtn) vaultSaveBtn.disabled = false;
    vaultDirty = true;
    if (vaultList) {
      [...vaultList.querySelectorAll("li")].forEach((li) => li.classList.remove("active"));
    }
  }

  async function saveVaultSnippet() {
    const title = vaultTitleInput ? vaultTitleInput.value.trim() : "";
    const body = vaultBodyInput ? vaultBodyInput.value : "";
    const tags = parseTags(vaultTagsInput ? vaultTagsInput.value : "");
    if (!title && !String(body).trim()) {
      showToast("Title or body required");
      return;
    }
    try {
      const isUpdate = !!activeVaultId;
      const r = await fetch(isUpdate ? `/api/vault/${encodeURIComponent(activeVaultId)}` : "/api/vault", {
        method: isUpdate ? "PATCH" : "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: title || body.slice(0, 60), body, tags }),
      });
      if (r.status === 401) return showAuth();
      const d = await r.json();
      if (!r.ok) {
        showToast(d.message || d.error || "Save failed");
        return;
      }
      const item = d.item || d;
      activeVaultId = item.id;
      showToast("Vault snippet saved");
      await loadVaultList();
      showVaultEditor(item);
    } catch (_) {
      showToast("Network error");
    }
  }

  async function deleteVaultSnippet() {
    if (!activeVaultId) return;
    if (!confirm("Delete this vault snippet?")) return;
    try {
      const r = await fetch(`/api/vault/${encodeURIComponent(activeVaultId)}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (r.status === 401) return showAuth();
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        showToast(d.error || "Delete failed");
        return;
      }
      activeVaultId = null;
      showVaultEditor(null);
      showToast("Deleted");
      loadVaultList();
    } catch (_) {
      showToast("Network error");
    }
  }

  if (vaultSearch) {
    let vaultSearchTimer = null;
    vaultSearch.addEventListener("input", () => {
      if (vaultSearchTimer) clearTimeout(vaultSearchTimer);
      vaultSearchTimer = setTimeout(() => loadVaultList(vaultSearch.value.trim()), 200);
    });
  }
  if (vaultNewBtn) vaultNewBtn.addEventListener("click", newVaultSnippet);
  if (vaultNewBtnMain) vaultNewBtnMain.addEventListener("click", newVaultSnippet);
  if (vaultSaveBtn) vaultSaveBtn.addEventListener("click", saveVaultSnippet);
  if (vaultDeleteBtn) vaultDeleteBtn.addEventListener("click", deleteVaultSnippet);
  if (vaultTitleInput) vaultTitleInput.addEventListener("input", markVaultDirty);
  if (vaultTagsInput) vaultTagsInput.addEventListener("input", markVaultDirty);
  if (vaultBodyInput) vaultBodyInput.addEventListener("input", markVaultDirty);


  checkAuth();
})();
