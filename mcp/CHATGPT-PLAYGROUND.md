# ChatGPT file playground (5-line usage)

1. Auth: `Authorization: Bearer <chatgpt-scoped nlk_…>` (token.sessions must include `chatgpt`) or human `morc_session` cookie.
2. List: `GET /api/playground/chatgpt` → `{files:[{name,size,updated_at},…]}`.
3. Upload: `PUT /api/playground/chatgpt/{name}` with raw body, `{"content":"…"}`, or multipart `file` (~25MB; names `[A-Za-z0-9._-]` only).
4. Download / delete: `GET /api/playground/chatgpt/{name}` and `DELETE /api/playground/chatgpt/{name}`.
5. Humans: Files UI label **chatgpt-playground** shares the same sandbox at `/opt/nullink/playground/chatgpt/`.
