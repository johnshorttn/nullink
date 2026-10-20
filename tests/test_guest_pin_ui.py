import pathlib, unittest
JS = (pathlib.Path(__file__).resolve().parent.parent / "static" / "guest.js").read_text()
class GuestPinUiTest(unittest.TestCase):
    def test_pin_card_has_copy_countdown_and_fallback(self):
        for s in ("guest-pin-copy", "Copied \\u2713", "execCommand(\"copy\")", "navigator.clipboard", "Expires in ", "Code expired", "New code", "guest-pin-x"):
            self.assertIn(s, JS)
    def test_pin_not_inside_rerendered_list(self):
        self.assertNotIn("guest-pin-out", JS)
        self.assertIn("document.body.appendChild(c)", JS)
