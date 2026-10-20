"""All DeepSeek web-UI selectors and text patterns used by the bridge, in ONE place.

When chat.deepseek.com changes its DOM, patch this file and restart:
    sudo systemctl restart nullink-deepseek-bridge

Strategy: role/text/semantic hooks first, DeepSeek's stable `ds-*` product
classes next, hashed classes (e.g. `._4d41763`) only as last-resort fallbacks.
Lists are tried in order; the first selector that matches wins.
"""

BASE_URL = "https://chat.deepseek.com/"
# Conversation permalinks look like https://chat.deepseek.com/a/chat/s/<uuid>
CONVERSATION_URL_RE = r"^https://chat\.deepseek\.com/a/chat/s/[0-9a-fA-F-]{36}"

# ---- logged-out detection -------------------------------------------------
# URL fragments that mean "not signed in".
LOGIN_URL_PARTS = ["/sign_in", "/sign_up", "/login", "/register"]
# Visible elements that only exist on the sign-in form.
LOGIN_FORM_SELECTORS = [
    "input[type='password']",
    "input[placeholder*='Phone number' i]",
    "input[placeholder*='email' i]",
]
LOGIN_BUTTON_TEXT_RE = r"^(Log in|Sign in|登录)$"

# ---- verification / captcha detection (never solved, only reported) ------
CAPTCHA_IFRAME_SRC_PARTS = ["challenges.cloudflare.com", "captcha", "turnstile", "geetest", "hcaptcha", "recaptcha"]
CAPTCHA_TITLE_RE = r"(just a moment|attention required|verify you are human|human verification|security check|captcha)"
# Only matched against short page/toast/dialog text, not chat content.
# Seen live 2026-10-06 on cold start: title "Human Verification", body "Let's confirm you are human ... security check".
CAPTCHA_TEXT_RE = r"(verify you are human|confirm you are human|are you a robot|not a bot|human verification|security check|captcha|人机验证|安全验证|请完成验证|拖动滑块)"

# ---- composer -------------------------------------------------------------
# The chat input. role=textbox is checked first by the worker, then these.
INPUT_SELECTORS = [
    "textarea#chat-input",
    "textarea[name='search']",
    "textarea[placeholder*='DeepSeek' i]",
    "textarea[placeholder*='message' i]",
    "div[contenteditable='true'][role='textbox']",
    "textarea",
]
# Fallback send button (normally we just press Enter). Searched inside the
# nearest ancestor of the input that has several buttons; the LAST enabled
# icon button there is the send/stop button in the current UI.
COMPOSER_BUTTON_SELECTOR = "[role='button'], button"

# ---- conversation ---------------------------------------------------------
# One chat turn (user or assistant).
MESSAGE_SELECTORS = ["div.ds-message", "[data-message-author-role]"]
# Final-answer containers inside an assistant turn (most specific first).
ANSWER_SELECTORS = [".ds-markdown", ".ds-assistant-message-main-content"]
# Reasoning ("DeepThink") blocks: never part of the posted answer.
THINKING_SELECTORS = [".ds-think-content", "._5255ff8._4d41763", "._4d41763"]
# Icon buttons in the copy/regenerate row that appears after a FINISHED answer.
ICON_BUTTON_SELECTOR = ".ds-icon-button, [role='button']:has(svg)"
# React prop on the answer element that holds the raw markdown source.
MARKDOWN_PROP_NAMES = ["markdown"]
# Code block parts (for the HTML -> markdown fallback converter).
CODE_BLOCK_SELECTOR = ".md-code-block"
CODE_LANG_SELECTORS = [".md-code-block-banner span", "[class*='banner'] span", "[class*='lang']"]
TOAST_SELECTORS = [".ds-toast", "[role='alert']", "[role='status']", ".ds-notification"]

# ---- answer-level error text (checked only on SHORT answers/toasts) ------
BUSY_RE = r"(server is busy|服务器繁忙|try again later|稍后再试|network error|网络错误)"
RATE_LIMIT_RE = r"(too many requests|too frequent|sending messages too fast|rate limit|reached (the|your) (daily |usage )?limit|usage limit|次数已达上限|请求过于频繁|达到上限)"
CONTEXT_FULL_RE = r"(maximum length|length limit|conversation is too long|上下文长度|长度上限|对话长度)"
