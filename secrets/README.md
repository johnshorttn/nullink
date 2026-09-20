# Secrets (not in git)

Place runtime secrets here on the server only, for example:
- `CURRENT_PIN.txt` / OTP store
- `totp.json` (authenticator secret and hashed recovery codes)
- session secret
- Bearer tokens
- Slack webhook URL

Never commit real credentials.
