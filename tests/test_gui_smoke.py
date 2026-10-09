"""Headless smoke test of the GTK interface.

Skipped when GTK 3 or a display is unavailable. CI runs it under xvfb-run with
python3-gi and gir1.2-gtk-3.0 installed. No helper is called: the window is
built from a fake status, exactly as after sign-in.
"""

import os
import sys
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

try:
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib, Gtk

    GTK_READY = Gtk.init_check(sys.argv)[0] if hasattr(Gtk, "init_check") else bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    GTK_READY = False


def fake_status(protected: bool) -> dict:
    lists = {key: {"enabled": protected and key != "social", "domain_count": 10 if protected else 0,
                   "updated_at": "2026-10-01T00:00:00+00:00" if protected else None}
             for key in ("adult", "gambling", "social", "malware")}
    return {
        "version": "test", "configured": True, "lists": lists,
        "strict_mode": {"enabled": protected}, "browser_policies": protected, "dns_engine": protected,
        "manual_count": 1, "tracked_ip_count": 0, "total_count": 31, "smart_sync": {"last_run": None},
        "entries": [{"id": "1", "value": "example.org", "kind": "domain", "category": "Social",
                     "smart": True, "resolved_ips": [], "created_at": "2026-10-01T00:00:00+00:00"}],
        "squid_proxy": {"enabled": False, "running": False, "installed": True, "keywords": ["porn", "xxx"]},
    }


@unittest.skipUnless(GTK_READY, "GTK 3 with a display is not available")
class MainWindowSmokeTests(unittest.TestCase):
    def setUp(self):
        import eduka_block

        self.ui = eduka_block
        self.ui.CURRENT_LANGUAGE = "en"

    def pump(self):
        while Gtk.events_pending():
            Gtk.main_iteration()

    def test_dashboard_reflects_protection_level(self):
        window = self.ui.MainWindow(fake_status(protected=False))
        self.addCleanup(window.destroy)
        self.pump()
        self.assertEqual(window.hero_title.get_text(), self.ui.T("hero_weak"))
        self.assertTrue(window.recommended_button.get_visible())
        window.load_status(fake_status(protected=True))
        self.assertEqual(window.hero_title.get_text(), self.ui.T("hero_strong"))
        self.assertFalse(window.recommended_button.get_visible())
        self.assertTrue(window.list_switches["adult"].get_state())
        self.assertFalse(window.list_switches["social"].get_state())

    def test_turn_on_and_turn_off_buttons_follow_the_state(self):
        window = self.ui.MainWindow(fake_status(protected=False))
        self.addCleanup(window.destroy)
        self.assertTrue(window.recommended_button.get_visible())
        self.assertFalse(window.turn_off_button.get_visible())
        window.load_status(fake_status(protected=True))
        self.assertFalse(window.recommended_button.get_visible())
        self.assertTrue(window.turn_off_button.get_visible())
        sent = []
        window.configure = sent.append
        self.ui.confirm = lambda *args, **kwargs: True
        window.on_turn_off()
        self.assertEqual(sent[0]["strict"], False)
        self.assertFalse(any(sent[0]["lists"].values()))

    def test_squid_has_its_own_page(self):
        window = self.ui.MainWindow(fake_status(protected=True))
        self.addCleanup(window.destroy)
        window.select_page("squid")
        self.pump()
        self.assertEqual(window.stack.get_visible_child_name(), "squid")
        self.assertEqual(len(window.squid_flow.get_children()), 2)

    def test_exactly_one_navigation_item_is_selected(self):
        window = self.ui.MainWindow(fake_status(protected=True))
        self.addCleanup(window.destroy)
        for name in ("websites", "categories", "advanced", "dashboard", "dashboard"):
            window.nav_buttons[name].clicked() if name != "dashboard" else window.select_page(name)
            self.pump()
            active = [key for key, nav in window.nav_buttons.items() if nav.get_active()]
            self.assertEqual(active, [name])
            self.assertEqual(window.stack.get_visible_child_name(), name)

    def test_rules_search_and_busy_guard(self):
        window = self.ui.MainWindow(fake_status(protected=True))
        self.addCleanup(window.destroy)
        self.assertEqual(window.list_summary.get_text(), self.ui.T("rules_shown_all", count=1))
        window.search.set_text("nothing-matches")
        window.on_search_changed()
        self.assertEqual(window.list_summary.get_text(), self.ui.T("rules_shown_filtered", shown=0, count=1))
        window.set_busy(True, "working")
        window.on_lock()
        self.assertFalse(window.lock_requested)
        window.set_busy(False)
        window.show_toast("done")
        self.assertTrue(window.toast_revealer.get_reveal_child())


@unittest.skipUnless(GTK_READY, "GTK 3 with a display is not available")
class AccountDialogSmokeTests(unittest.TestCase):
    def setUp(self):
        import eduka_block

        self.ui = eduka_block
        self.ui.CURRENT_LANGUAGE = "en"

    def test_login_offers_account_recovery(self):
        dialog = self.ui.AccountDialog("login")
        self.addCleanup(dialog.destroy)
        self.assertEqual(dialog.forgot_button.get_label(), self.ui.T("forgot_link"))
        responses = []
        dialog.connect("response", lambda _dialog, response: responses.append(response))
        dialog.forgot_button.clicked()
        self.assertEqual(responses, [self.ui.RESPONSE_FORGOT])

    def test_reset_dialog_requires_matching_new_password(self):
        dialog = self.ui.AccountDialog("reset")
        self.addCleanup(dialog.destroy)
        self.assertIsNone(dialog.forgot_button)
        self.assertEqual(dialog.heading.get_text(), self.ui.T("reset_title"))
        dialog.username.set_text("teacher")
        dialog.password.set_text("secret1")
        dialog.confirm_password.set_text("secret2")
        self.assertFalse(dialog.action_button.get_sensitive())
        dialog.confirm_password.set_text("secret1")
        self.assertTrue(dialog.action_button.get_sensitive())


if __name__ == "__main__":
    unittest.main()
