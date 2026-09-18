# Nullink playbook (Morc)

**Trigger:** When John says **"Nullink"** (or asks for the PC chat bridge / private workspace link / PM / files).

## Goal
Give John a working public HTTPS URL + a fresh 6-digit PIN so he can open **Nullink** (chat + PM files) from any browser.

## Checklist

1. **Server on 8766**
   - Confirm: `ss -tlnp | grep 8766` or `curl -s http://127.0.0.1:8766/health`
   - Expect: `{"ok": true, "service": "nullink", "port": 8766, "pm": true}`
   - If down: `cd /workspace/chat-bridge && nohup python3 server.py > /tmp/nullink-server.log 2>&1 &`
   - **Never** touch port **8765** (YMS / CMP).

2. **Public tunnel (prefer nullink-named subdomain)**
   - Prefer: `npx --yes localtunnel --port 8766 --subdomain nullink`
     → URL like `https://nullink.loca.lt`
   - Fallbacks: `--subdomain nullink-app`, `nullink-secure`, then `nullink-pc`
   - Also keep cloudflared: `./cloudflared tunnel --url http://127.0.0.1:8766 --no-autoupdate`
     (random `*.trycloudflare.com` — no browser interstitial)
   - Kill only the **old 8766** tunnel before replacing; leave YMS/8765 alone.
   - Verify: `curl -sS -H 'Bypass-Tunnel-Reminder: 1' https://<host>/health`

3. **Mint / rotate OTP**
   - `python3 /workspace/chat-bridge/set_otp.py`
   - Clear PIN: `/workspace/chat-bridge/secrets/CURRENT_PIN.txt`
   - Do not log the PIN to shared logs; tell John in chat only.

4. **Reply to John in chat**
   - Public URL (prefer one containing **nullink**)
   - 6-digit PIN
   - Brief: branding is **Nullink**; session inside is still **Chief of Staff (Morc)**
   - Optional: Chat | Files tabs; Ask Morc for document review
   - Optional note: loca.lt may show a one-click interstitial the first visit — use CF URL if blocked

5. **Update `HOST.txt`**
   - Keep Public URL + PIDs current after any restart.

## PM features (v1)

### Labels
- Stored in `data/labels.json`
- Seed: **YMS**, **Nullink**, **Inbox**
- CRUD via UI chips (right-click chip to delete) or API
- Files can have multiple label ids; sidebar filters are multi-select

### File manager
- Registry: `data/files.json` — `id`, `name`, `path`, `labels[]`, `size`, `updated_at`, `source`
- Sources: `upload` | `registered` | `scratch`
- Physical storage under:
  - `uploads/<label-folder>/` for uploads/saves
  - `data/files/` vault for registered copies
  - `scratch/<id>-preview.txt` for Preview / Ask Morc
- Click text file → editor; binary → download
- Register helper (Morc): only paths under `/workspace/chat-bridge/` or `/workspace/athenaeum/` — **copied** into vault (no arbitrary FS exposure)
  ```
  python3 /workspace/chat-bridge/register_file.py /path/to/file.txt nullink
  ```

### Upload
- UI: Files tab → ↑ button
- `POST /api/files/upload (multi-file; any extension; 50MB/file; saved mode 0644)` multipart, session cookie, max **50MB**
- Allowed: text + common docs/images; blocked executables
- Writes `data/pending.upload` (+ mirrors `pending.notify`)

### Editor
- Monospace buffer with **line-number gutter**
- Save → `POST /api/files/save`
- Ctrl/Cmd+S to save

### Preview + Ask Morc flow
1. **Preview** — copies current buffer to `scratch/<id>-preview.txt` + `scratch/<id>-meta.json`.
   Does **not** notify Morc by itself.
2. **Ask Morc** — ensures a preview scratch exists; writes notify payload with:
   `path`, `file_id`, `name`, `labels`, `line_count`, optional `message`
   Sets `data/pending.notify` and `data/pending.ask`; also posts a chat line
   `[Ask Morc · <name>] …` so SSE surfaces it.
3. **Morc handling**
   - Watch `data/pending.notify` / `data/pending.ask` (kind `ask-morc`)
   - Read the scratch file; **cite line numbers** when commenting
   - Patch the scratch file in place (`scratch/<id>-preview.txt`) — do not overwrite vault until John accepts
   - Reply in chat via `reply.py` summarizing changes / questions
4. **John UI**
   - **Pull updates** — reload scratch into editor buffer
   - **Accept** — load scratch into editor (still unsaved)
   - **Save** — write editor buffer to the vault/uploaded file

## Paths
| What | Path |
|------|------|
| App | `/workspace/chat-bridge/` |
| Host card | `/workspace/chat-bridge/HOST.txt` |
| PIN (clear) | `/workspace/chat-bridge/secrets/CURRENT_PIN.txt` |
| Labels | `data/labels.json` |
| Files registry | `data/files.json` |
| Uploads | `uploads/` |
| Vault | `data/files/` |
| Scratch | `scratch/` |
| Pending | `data/pending.notify`, `pending.upload`, `pending.ask` |
| Reply helper | `python3 reply.py "…"` |
| Register helper | `python3 register_file.py <path> [labels…]` |

## Branding (do not regress)
- Site title / header / login / chrome: **Nullink**
- Tagline: "Secure session access" / "private workspace PM"
- Session label: **Chief of Staff (Morc)** (id `morc`)

## How to test (quick)
1. Open public URL → enter PIN → see Chat | Files tabs
2. Files → New or Upload a `.txt` → edit with gutter → Save
3. Preview → confirm `scratch/*-preview.txt` exists, no ask pending alone
4. Ask Morc with a note → check chat + `pending.ask`
5. Morc edits scratch → John Pull updates → Accept → Save

## Webhook wake

- Config: `/workspace/chat-bridge/secrets/webhook.json` (template: `secrets/webhook.json.example`).
- fill webhook.json from Nullink webhook wake routine panel; keep it absent or `enabled:false` until Morc supplies the URL and auth header.
- The server sends fire-and-forget JSON for user messages, Ask Morc, and uploads; failures go to `/tmp/nullink-webhook.log` and never block the UI response.
- Test a configured endpoint with `python3 /workspace/chat-bridge/scripts/test_webhook.py`.

## Slice D — Quick paste → task (F3) + Vault snippets (F7)

### Selection toolbar
- Select text in chat bubbles or the file editor → floating toolbar: **Make task** / **Add label** / **Ask Morc**
- Make task → `POST /api/tasks` → `data/tasks.json` (0600); open tasks appear in Inbox (`kind: task`)
- Add label → `POST /api/selection/label` → paste file under `uploads/<label>/` with that label
- Ask Morc → `POST /api/files/ask-morc` with selection as scratch content

### Vault
- Tab **Vault** — OTP-gated snippets (title, body, tags), searchable, not in chat history
- Store: `data/vault/<id>.json` mode **0600** (dir 0700)
- API: `GET/POST /api/vault`, `GET/PATCH/DELETE /api/vault/<id>`
