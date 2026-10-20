"""All ChatGPT web-UI selectors and text patterns used by the Jinx bridge, in ONE place.

When chatgpt.com changes its DOM, patch this file and restart:
    sudo systemctl restart nullink-chatgpt-bridge

Lists are tried in order; the first selector that matches wins.
"""

BASE_URL = "https://chatgpt.com/"
# Conversation permalinks: https://chatgpt.com/c/<uuid>  (or inside a project/GPT: /g/<id>/c/<uuid>)
CONVERSATION_URL_RE = r"^https://chatgpt\.com/(g/[^/]+/)?c/[0-9a-fA-F-]{36}"

# ---- logged-out detection -------------------------------------------------
# chatgpt.com lets logged-out visitors chat anonymously, so a visible composer does NOT mean signed in.
# Any visible "Log in" button => logged out.
LOGIN_URL_PARTS = ["auth.openai.com", "/auth/login", "/log-in", "auth0.openai.com", "/u/login"]
LOGIN_FORM_SELECTORS = [
    "button[data-testid='login-button']",
    "a[data-testid='login-button']",
    "input[type='password']",
    "input[name='email'][type='email']",
]
# Signed-in-only hooks (any one visible => signed in).
SIGNED_IN_SELECTORS = [
    "[data-testid='accounts-profile-button']",
    "button[data-testid='profile-button']",
    "nav [data-testid='history-item-0']",
    "[data-testid='create-new-chat-button']",
]

# ---- verification / captcha detection (never solved, only reported) ------
CAPTCHA_IFRAME_SRC_PARTS = ["challenges.cloudflare.com", "turnstile", "arkoselabs", "funcaptcha", "hcaptcha", "recaptcha"]
CAPTCHA_TITLE_RE = r"(just a moment|attention required|verify you are human|human verification|security check|captcha)"
CAPTCHA_TEXT_RE = r"(verify you are human|confirm you are human|are you a robot|not a bot|human verification|security check|captcha|unusual activity)"

# ---- composer -------------------------------------------------------------
INPUT_SELECTORS = [
    "#prompt-textarea",
    "div.ProseMirror[contenteditable='true']",
    "textarea[name='prompt-textarea']",
    "div[contenteditable='true'][role='textbox']",
    "textarea",
]
SEND_BUTTON_SELECTORS = ["button[data-testid='send-button']", "button[aria-label*='Send' i]"]
STOP_BUTTON_SELECTORS = ["button[data-testid='stop-button']", "button[aria-label*='Stop' i]"]
COMPOSER_BUTTON_SELECTOR = "[role='button'], button"

# ---- conversation ---------------------------------------------------------
MESSAGE_SELECTORS = ["[data-message-author-role]"]
ANSWER_SELECTORS = [".markdown", ".prose"]
# Reasoning blocks are never part of the posted answer.
THINKING_SELECTORS = ["[data-testid*='reasoning']", "[class*='reasoning-']"]
# Copy button that appears under a FINISHED assistant turn.
DONE_ACTION_SELECTORS = ["[data-testid='copy-turn-action-button']", "button[aria-label='Copy']"]
ICON_BUTTON_SELECTOR = "[data-testid='copy-turn-action-button'], [data-testid*='turn-action']"
MARKDOWN_PROP_NAMES = ["markdown"]
CODE_BLOCK_SELECTOR = "pre"
CODE_LANG_SELECTORS = ["pre > div > div:first-child", "[class*='lang']"]
TOAST_SELECTORS = ["[role='alert']", "[data-testid*='toast']", ".toast-root"]

# ---- answer-level error text (checked only on SHORT answers/toasts) ------
BUSY_RE = r"(something went wrong|network error|error generating a response|an error occurred|hmm\.\.\.something seems to have gone wrong)"
RATE_LIMIT_RE = r"(you'?ve reached (our|your|the) (limit|usage)|usage (cap|limit)|too many requests|you'?ve hit the (free plan )?limit|rate limit)"
CONTEXT_FULL_RE = r"(conversation is too long|maximum (context|conversation) length|start a new chat to continue)"
