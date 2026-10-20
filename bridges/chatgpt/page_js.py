"""JavaScript evaluated inside the ChatGPT page (shared with the DeepSeek bridge). Selectors come from cg_selectors.py."""

DETECT_JS = r"""
(cfg) => {
  const vis = (e) => !!e && !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const firstVis = (sels) => { for (const s of sels) { try { for (const e of document.querySelectorAll(s)) if (vis(e)) return e; } catch (err) {} } return null; };
  const txt = (sels) => { const out = []; for (const s of sels) { try { document.querySelectorAll(s).forEach((e) => { if (vis(e)) { const t = (e.innerText || '').trim(); if (t && t.length < 400) out.push(t); } }); } catch (err) {} } return out.join(' | ').slice(0, 1500); };
  const input = firstVis(cfg.input);
  const loginForm = !!firstVis(cfg.loginForm);
  const iframes = Array.from(document.querySelectorAll('iframe')).map((f) => f.src || '').filter(Boolean).slice(0, 20);
  return {
    url: location.href,
    title: document.title || '',
    hasInput: !!input,
    loginForm,
    iframes,
    toasts: txt(cfg.toasts),
    dialogs: txt(["[role='dialog']", "[aria-modal='true']"]),
    body: input ? '' : ((document.body && document.body.innerText) || '').slice(0, 2000),
  };
}
"""

SNAPSHOT_JS = r"""
(cfg) => {
  const qaFirst = (root, sels) => { for (const s of sels) { try { const r = root.querySelectorAll(s); if (r.length) return Array.from(r); } catch (e) {} } return []; };
  const matchesAny = (el, sels) => sels.some((s) => { try { return el.matches(s); } catch (e) { return false; } });
  const inThinking = (el) => cfg.thinking.some((s) => { try { return !!el.closest(s); } catch (e) { return false; } });
  const hasAny = (el, sels) => sels.some((s) => { try { return !!el.querySelector(s); } catch (e) { return false; } });
  const outermost = (arr) => arr.filter((a) => !arr.some((o) => o !== a && o.contains(a)));
  const vis = (e) => !!e && !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);

  // ---------- HTML -> markdown fallback converter ----------
  const blockify = (s) => s.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  const toMd = (root) => {
    const kids = (n, ctx) => Array.from(n.childNodes).map((c) => walk(c, ctx)).join('');
    const walk = (n, ctx) => {
      if (n.nodeType === 3) return n.nodeValue.replace(/\s+/g, ' ');
      if (n.nodeType !== 1) return '';
      const el = n; const tag = el.tagName.toLowerCase();
      if (matchesAny(el, cfg.thinking)) return '';
      if (['button', 'svg', 'style', 'script', 'noscript', 'textarea', 'input'].includes(tag) || el.getAttribute('role') === 'button') return '';
      const cls = el.classList;
      if (cls.contains('katex-display')) { const a = el.querySelector('annotation[encoding="application/x-tex"]'); if (a) return '\n\n$$' + a.textContent.trim() + '$$\n\n'; }
      if (cls.contains('katex')) { const a = el.querySelector('annotation[encoding="application/x-tex"]'); if (a) return '$' + a.textContent.trim() + '$'; }
      let isCode = tag === 'pre';
      try { isCode = isCode || el.matches(cfg.codeBlock); } catch (e) {}
      if (isCode) {
        const pre = tag === 'pre' ? el : el.querySelector('pre');
        if (pre) {
          let lang = '';
          const codeEl = pre.querySelector('code');
          const m = codeEl && String(codeEl.className || '').match(/language-([\w+#.-]+)/);
          if (m) lang = m[1];
          if (!lang && tag !== 'pre') {
            for (const s of cfg.codeLang) { try { const l = el.querySelector(s); const t = l && l.textContent.trim(); if (t && t.length < 24 && !/copy|复制|download|下载|run/i.test(t)) { lang = t; break; } } catch (e) {} }
          }
          const code = (pre.innerText || pre.textContent || '').replace(/\n$/, '');
          return '\n\n```' + lang.toLowerCase() + '\n' + code + '\n```\n\n';
        }
      }
      switch (tag) {
        case 'br': return '\n';
        case 'hr': return '\n\n---\n\n';
        case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6':
          return '\n\n' + '#'.repeat(parseInt(tag[1], 10)) + ' ' + kids(el, ctx).trim() + '\n\n';
        case 'p': return '\n\n' + kids(el, ctx).trim() + '\n\n';
        case 'strong': case 'b': { const t = kids(el, ctx); return t.trim() ? '**' + t.trim() + '**' : t; }
        case 'em': case 'i': { const t = kids(el, ctx); return t.trim() ? '*' + t.trim() + '*' : t; }
        case 'del': case 's': { const t = kids(el, ctx); return t.trim() ? '~~' + t.trim() + '~~' : t; }
        case 'code': return '`' + el.textContent + '`';
        case 'a': { const t = kids(el, ctx).trim(); const h = el.getAttribute('href') || ''; return (h && !/^javascript:/i.test(h)) ? '[' + (t || h) + '](' + h + ')' : t; }
        case 'blockquote': { const t = blockify(kids(el, ctx)); return '\n\n' + t.split('\n').map((l) => '> ' + l).join('\n') + '\n\n'; }
        case 'ul': case 'ol': {
          const depth = ctx.depth || 0; let i = parseInt(el.getAttribute('start') || '1', 10) || 1;
          const items = Array.from(el.children).filter((c) => c.tagName.toLowerCase() === 'li').map((li) => {
            const marker = tag === 'ol' ? (i++) + '. ' : '- ';
            const body = blockify(kids(li, Object.assign({}, ctx, { depth: depth + 1 })));
            const pad = ' '.repeat(marker.length);
            return marker + body.split('\n').map((l, k) => (k === 0 || !l) ? l : pad + l).join('\n');
          });
          return depth > 0 ? '\n' + items.join('\n') + '\n' : '\n\n' + items.join('\n') + '\n\n';
        }
        case 'table': {
          const rows = Array.from(el.querySelectorAll('tr')).map((tr) => Array.from(tr.children).map((td) => blockify(kids(td, ctx)).replace(/\n+/g, ' ').replace(/\|/g, '\\|')));
          if (!rows.length) return '';
          const w = Math.max(...rows.map((r) => r.length));
          const line = (r) => '| ' + Array.from({ length: w }, (_, k) => r[k] || '').join(' | ') + ' |';
          return '\n\n' + [line(rows[0]), '|' + ' --- |'.repeat(w), ...rows.slice(1).map(line)].join('\n') + '\n\n';
        }
        default: return kids(el, ctx);
      }
    };
    return blockify(walk(root, {}));
  };

  // ---------- raw markdown from React props (best fidelity) ----------
  const reactMarkdown = (el) => {
    for (let node = el, d = 0; node && d < 4; node = node.parentElement, d++) {
      const keys = Object.keys(node);
      const pk = keys.find((k) => k.startsWith('__reactProps$'));
      if (pk) { const p = node[pk]; for (const n of cfg.mdProps) if (p && typeof p[n] === 'string' && p[n].trim()) return p[n]; }
      const fk = keys.find((k) => k.startsWith('__reactFiber$'));
      if (fk) {
        let f = node[fk];
        for (let i = 0; f && i < 10; i++, f = f.return) {
          const p = f.memoizedProps;
          if (p && typeof p === 'object') for (const n of cfg.mdProps) if (typeof p[n] === 'string' && p[n].trim()) return p[n];
        }
      }
    }
    return null;
  };

  const answerEls = (root) => {
    for (const s of cfg.answer) {
      let found = [];
      try { found = Array.from(root.querySelectorAll(s)).filter((a) => !inThinking(a)); } catch (e) {}
      found = outermost(found);
      if (found.length) return found;
    }
    return [];
  };

  let msgs = outermost(qaFirst(document, cfg.message));
  const turns = msgs.map((m) => {
    const attr = m.getAttribute('data-message-author-role');
    const role = attr ? (attr === 'user' ? 'user' : 'assistant') : ((hasAny(m, cfg.answer) || hasAny(m, cfg.thinking)) ? 'assistant' : 'user');
    return { el: m, role };
  });
  let lastUserIdx = -1;
  turns.forEach((t, i) => { if (t.role === 'user') lastUserIdx = i; });
  let asst = null;
  for (let i = turns.length - 1; i > lastUserIdx; i--) if (turns[i].role === 'assistant') { asst = turns[i].el; break; }
  const lastUserText = lastUserIdx >= 0 ? (turns[lastUserIdx].el.innerText || '').trim().slice(0, 4000) : '';
  const answersCount = answerEls(document).length;

  let text = '', md = null, conv = '', thinking = false, hasActions = false;
  if (asst) {
    const els = answerEls(asst);
    text = els.map((a) => (a.innerText || '').trim()).filter(Boolean).join('\n\n');
    conv = els.map((a) => toMd(a)).filter(Boolean).join('\n\n');
    const mds = els.map((a) => reactMarkdown(a));
    if (mds.length && mds.every((x) => typeof x === 'string')) md = mds.join('\n\n');
    thinking = hasAny(asst, cfg.thinking);
    const rows = [asst.nextElementSibling, asst.parentElement && asst.parentElement.nextElementSibling];
    for (const r of rows) {
      if (!r || r.querySelector('textarea')) continue;
      let n = 0; try { n = Array.from(r.querySelectorAll(cfg.iconButton)).filter(vis).length; } catch (e) {}
      if (n >= 2) { hasActions = true; break; }
    }
  }
  return { turns: turns.length, lastUserText, answersCount, asstFound: !!asst, text, md, conv, thinking, hasActions, url: location.href };
}
"""
