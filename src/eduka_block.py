#!/usr/bin/python3
"""Eduka-Block GTK interface."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GdkPixbuf, GLib, Gtk, Pango  # noqa: E402


# Prefer modules next to this file when running from a source checkout; the
# installed /usr/bin/eduka-block has no neighbours and uses the library dir.
SOURCE_DIR = Path(__file__).resolve().parent
LIB_DIR = Path("/usr/lib/eduka-block")
if (SOURCE_DIR / "eduka_block_common.py").is_file():
    sys.path.insert(0, str(SOURCE_DIR))
else:
    sys.path.insert(0, str(LIB_DIR))

from eduka_block_common import (  # noqa: E402
    APP_VERSION,
    CATEGORIES,
    CREDENTIALS_PATH,
    ValidationError,
    export_rules_text,
    parse_rules_text,
    rule_target,
    verify_credentials,
)
from eduka_block_data import RECOMMENDED_LISTS  # noqa: E402
from eduka_block_i18n import LANGUAGES, load_language, save_language, tr  # noqa: E402


HELPER = "/usr/lib/eduka-block/eduka-block-helper"
ICON = "/usr/share/icons/hicolor/scalable/apps/eduka-block.svg"
CSS = "/usr/share/eduka-block/eduka-block.css"
CONFIG_PATH = Path.home() / ".config" / "eduka-block" / "settings.json"
AUTO_LOCK_SECONDS = 600
MAX_LOGIN_ATTEMPTS = 5
MAX_IMPORT_ITEMS = 1000
MAX_IMPORT_FILE_BYTES = 2 * 1024 * 1024
TOAST_SECONDS = 4
RESPONSE_CHANGE_ACCOUNT = 1001
CURRENT_LANGUAGE = load_language(CONFIG_PATH)

# Seconds allowed per helper action. The helper may wait up to 90 s for the
# system lock, so every timeout leaves room for that plus the work itself.
HELPER_TIMEOUTS = {
    "status": 30,
    "protection-configure": 420,
    "squid-configure": 180,
    "sync-smart-ips": 600,
    "import": 180,
}
DEFAULT_TIMEOUT = 150


def T(key: str, **values) -> str:
    return tr(key, CURRENT_LANGUAGE, **values)


def set_language(language: str) -> None:
    global CURRENT_LANGUAGE
    if language not in LANGUAGES:
        language = "en"
    CURRENT_LANGUAGE = language
    try:
        save_language(CONFIG_PATH, language)
    except OSError:
        pass


CATEGORY_KEYS = {
    "Manual": "category_manual",
    "Adult": "category_adult",
    "Harmful": "category_harmful",
    "Malware": "category_malware",
    "Gambling": "category_gambling",
    "Social": "category_social",
    "Other": "category_other",
}
TYPE_KEYS = {
    "domain": "type_domain",
    "ipv4": "type_ipv4",
    "ipv6": "type_ipv6",
    "ipv4_network": "type_ipv4_network",
    "ipv6_network": "type_ipv6_network",
}
# Category blocklists shown on the Categories page: (key, icon).
LIST_ROWS = (
    ("adult", "action-unavailable-symbolic"),
    ("gambling", "applications-games-symbolic"),
    ("social", "system-users-symbolic"),
    ("malware", "dialog-warning-symbolic"),
)
NAV_PAGES = (
    ("dashboard", "nav_dashboard", "security-high-symbolic"),
    ("websites", "nav_websites", "web-browser-symbolic"),
    ("categories", "nav_categories", "view-grid-symbolic"),
    ("advanced", "nav_advanced", "preferences-system-symbolic"),
)
STATE_CLASSES = ("status-ok", "status-warning", "status-error")

# Tree model columns.
COL_ID, COL_STATUS, COL_TARGET, COL_TYPE, COL_CATEGORY, COL_COVERAGE, COL_ADDED = range(7)


class AppError(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(T(code, detail=detail))


def helper_call(action: str, payload: dict | None = None, privileged: bool = False) -> dict:
    command = [HELPER, action]
    if privileged:
        command.insert(0, "pkexec")
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(payload or {}, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=HELPER_TIMEOUTS.get(action, DEFAULT_TIMEOUT),
            check=False,
        )
    except FileNotFoundError as exc:
        raise AppError("err_component_missing") from exc
    except subprocess.TimeoutExpired as exc:
        raise AppError("err_timeout") from exc
    if completed.returncode in {126, 127} and privileged:
        raise AppError("err_authorization")
    try:
        response = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise AppError("err_helper_response", completed.stderr.strip()) from exc
    if not response.get("ok"):
        raise AppError(str(response.get("error_code", "err_internal")), str(response.get("detail", "")))
    return response["data"]


def local_time(value: object) -> str:
    """Format a stored UTC ISO timestamp in the computer's local time."""
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value)).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(value)[:16].replace("T", " ")


def set_state_class(widget: Gtk.Widget, state: str) -> None:
    context = widget.get_style_context()
    for style_class in STATE_CLASSES:
        context.remove_class(style_class)
    context.add_class(f"status-{state}")


def add_classes(widget: Gtk.Widget, *classes: str) -> Gtk.Widget:
    context = widget.get_style_context()
    for style_class in classes:
        context.add_class(style_class)
    return widget


def label(text: str = "", *classes: str, wrap: bool = False, xalign: float = 0) -> Gtk.Label:
    widget = Gtk.Label(label=text, xalign=xalign)
    if wrap:
        widget.set_line_wrap(True)
        widget.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    return add_classes(widget, *classes)


def icon(name: str, size: int, *classes: str) -> Gtk.Image:
    image = Gtk.Image.new_from_icon_name(name, Gtk.IconSize.BUTTON)
    image.set_pixel_size(size)
    return add_classes(image, *classes)


def logo_image(size: int) -> Gtk.Image:
    """The application logo scaled to ``size`` pixels (SVGs load at full size otherwise)."""
    for candidate in (Path(ICON), SOURCE_DIR.parent / "assets" / "eduka-block.svg"):
        if candidate.exists():
            try:
                pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(candidate), size, size, True)
                return Gtk.Image.new_from_pixbuf(pixbuf)
            except GLib.Error:
                break
    return icon("security-high-symbolic", size)


def short_time(value: object) -> str:
    """"14:05" for today, otherwise "09-28 14:05"."""
    text = local_time(value)
    if not text:
        return "—"
    today = datetime.now().strftime("%Y-%m-%d")
    return text[11:] if text.startswith(today) else text[5:]


def button(text: str, callback, *classes: str, icon_name: str | None = None) -> Gtk.Button:
    widget = Gtk.Button()
    content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    content.set_halign(Gtk.Align.CENTER)
    if icon_name:
        content.pack_start(icon(icon_name, 16), False, False, 0)
    content.pack_start(Gtk.Label(label=text), False, False, 0)
    widget.add(content)
    widget.connect("clicked", callback)
    return add_classes(widget, *classes)


def sync_switch(switch: Gtk.Switch, value: bool) -> None:
    """Set both "active" and "state": handlers that return True defer "state"."""
    switch.set_active(value)
    switch.set_state(value)


def card(spacing: int = 12, *classes: str) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    return add_classes(box, "card", *classes)


def load_css() -> None:
    provider = Gtk.CssProvider()
    css_path = SOURCE_DIR.parent / "assets" / "eduka-block.css"
    if not css_path.exists():
        css_path = Path(CSS)
    try:
        provider.load_from_path(str(css_path))
        screen = Gdk.Screen.get_default()
        if screen:
            Gtk.StyleContext.add_provider_for_screen(
                screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    except GLib.Error:
        pass


def message(parent: Gtk.Window | None, title: str, body: str, error: bool = False) -> None:
    dialog = Gtk.MessageDialog(
        transient_for=parent,
        modal=True,
        message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
        buttons=Gtk.ButtonsType.OK,
        text=title,
    )
    dialog.format_secondary_text(body)
    dialog.run()
    dialog.destroy()


def confirm(parent: Gtk.Window, title: str, body: str, action_key: str = "continue") -> bool:
    dialog = Gtk.MessageDialog(
        transient_for=parent,
        modal=True,
        message_type=Gtk.MessageType.QUESTION,
        buttons=Gtk.ButtonsType.CANCEL,
        text=title,
    )
    dialog.format_secondary_text(body)
    dialog.add_button(T(action_key), Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    result = dialog.run() == Gtk.ResponseType.OK
    dialog.destroy()
    return result


def protection_layers(status: dict) -> list[tuple[str, bool]]:
    """(label key, active) for each layer the dashboard scores."""
    lists = status.get("lists", {})
    return [
        ("layer_adult", bool(lists.get("adult", {}).get("enabled"))),
        ("layer_gambling", bool(lists.get("gambling", {}).get("enabled"))),
        ("layer_malware", bool(lists.get("malware", {}).get("enabled"))),
        ("layer_strict", bool(status.get("strict_mode", {}).get("enabled"))),
        ("layer_browsers", bool(status.get("browser_policies"))),
        ("layer_dns", bool(status.get("dns_engine"))),
    ]


def recommended_active(status: dict) -> bool:
    lists = status.get("lists", {})
    return all(lists.get(key, {}).get("enabled") for key in RECOMMENDED_LISTS) and bool(
        status.get("strict_mode", {}).get("enabled")
    )


class AccountDialog(Gtk.Dialog):
    """Login ("login"), first-run ("setup") or account replacement ("change")."""

    def __init__(self, mode: str, parent: Gtk.Window | None = None):
        super().__init__(transient_for=parent, modal=True)
        self.mode = mode
        self.setup = mode != "login"
        self.set_default_size(400, -1)
        self.set_resizable(False)
        self.set_position(Gtk.WindowPosition.CENTER)
        add_classes(self, "auth-dialog")
        self.cancel_button = self.add_button("", Gtk.ResponseType.CANCEL)
        self.change_button = None
        if mode == "login":
            self.change_button = self.add_button("", RESPONSE_CHANGE_ACCOUNT)
            add_classes(self.change_button, "flat-button")
        self.action_button = self.add_button("", Gtk.ResponseType.OK)
        add_classes(self.action_button, "suggested-action")
        self.set_default_response(Gtk.ResponseType.OK)

        box = self.get_content_area()
        box.set_spacing(0)
        box.set_border_width(0)
        panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        add_classes(panel, "auth-panel")
        box.pack_start(panel, True, True, 0)

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.language_combo = Gtk.ComboBoxText()
        for code, name in LANGUAGES.items():
            self.language_combo.append(code, name)
        self.language_combo.set_active_id(CURRENT_LANGUAGE)
        self.language_combo.connect("changed", self.on_language)
        top.pack_end(self.language_combo, False, False, 0)
        panel.pack_start(top, False, False, 0)

        logo = add_classes(logo_image(72), "auth-logo")
        panel.pack_start(logo, False, False, 4)
        self.heading = label("", "auth-title", xalign=0.5)
        panel.pack_start(self.heading, False, False, 0)
        self.note = label("", "auth-note", wrap=True, xalign=0.5)
        self.note.set_justify(Gtk.Justification.CENTER)
        self.note.set_max_width_chars(44)
        panel.pack_start(self.note, False, False, 6)

        self.username_label = label("", "field-label")
        panel.pack_start(self.username_label, False, False, 0)
        self.username = Gtk.Entry()
        self.username.set_activates_default(True)
        panel.pack_start(self.username, False, False, 0)
        self.password_label = label("", "field-label")
        panel.pack_start(self.password_label, False, False, 0)
        self.password = self.password_entry()
        panel.pack_start(self.password, False, False, 0)
        self.confirm_label = None
        self.confirm_password = None
        self.password_status = None
        if self.setup:
            self.confirm_label = label("", "field-label")
            panel.pack_start(self.confirm_label, False, False, 0)
            self.confirm_password = self.password_entry()
            panel.pack_start(self.confirm_password, False, False, 0)
            self.password_status = label("", "password-status", wrap=True)
            panel.pack_start(self.password_status, False, False, 4)
            self.username.connect("changed", self.on_account_field_changed)
            self.password.connect("changed", self.on_account_field_changed)
            self.confirm_password.connect("changed", self.on_account_field_changed)
        self.update_text()
        self.update_account_validation()
        self.show_all()

    @staticmethod
    def password_entry() -> Gtk.Entry:
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        entry.set_activates_default(True)
        # Eye icon toggles visibility so parents can check what they typed.
        entry.set_icon_from_icon_name(Gtk.EntryIconPosition.SECONDARY, "view-reveal-symbolic")
        entry.connect(
            "icon-press", lambda widget, *_: widget.set_visibility(not widget.get_visibility())
        )
        return entry

    def update_text(self) -> None:
        titles = {"setup": "setup_title", "login": "login_title", "change": "change_account_title"}
        notes = {"setup": "setup_note", "login": "login_note", "change": "change_account_note"}
        actions = {"setup": "create_account", "login": "sign_in", "change": "save_account"}
        self.set_title("Eduka-Block")
        self.cancel_button.set_label(T("cancel"))
        self.action_button.set_label(T(actions[self.mode]))
        if self.change_button:
            self.change_button.set_label(T("change_account"))
        self.heading.set_text(T(titles[self.mode]))
        self.note.set_text(T(notes[self.mode]))
        self.username_label.set_text(T("username"))
        self.username.set_placeholder_text(T("username_hint"))
        self.password_label.set_text(T("password"))
        self.password.set_placeholder_text(T("password_minimum") if self.setup else "")
        self.password.set_icon_tooltip_text(Gtk.EntryIconPosition.SECONDARY, T("show_password"))
        if self.confirm_label:
            self.confirm_label.set_text(T("repeat_password"))
            self.confirm_password.set_icon_tooltip_text(
                Gtk.EntryIconPosition.SECONDARY, T("show_password")
            )
            self.update_account_validation()

    def on_language(self, combo: Gtk.ComboBoxText) -> None:
        code = combo.get_active_id()
        if code:
            set_language(code)
            self.update_text()

    def values(self) -> tuple[str, str]:
        return self.username.get_text().strip(), self.password.get_text()

    def passwords_match(self) -> bool:
        return not self.setup or self.password.get_text() == self.confirm_password.get_text()

    def on_account_field_changed(self, *_args) -> None:
        self.update_account_validation()

    def update_account_validation(self) -> None:
        if not self.setup or self.password_status is None:
            return
        password = self.password.get_text()
        confirmation = self.confirm_password.get_text()
        if len(password) < 5:
            self.password_status.set_text(T("password_minimum"))
            set_state_class(self.password_status, "warning")
        elif not confirmation:
            self.password_status.set_text(T("password_confirm_prompt"))
            set_state_class(self.password_status, "warning")
        elif password != confirmation:
            self.password_status.set_text(T("password_mismatch_inline"))
            set_state_class(self.password_status, "error")
        else:
            self.password_status.set_text(T("password_ready"))
            set_state_class(self.password_status, "ok")

        username_valid = 3 <= len(self.username.get_text().strip()) <= 64
        self.action_button.set_sensitive(
            username_valid and len(password) >= 5 and password == confirmation
        )


def run_account_change(parent: Gtk.Window | None) -> str | None:
    """Show the change-account dialog; return the new username once saved."""
    dialog = AccountDialog("change", parent=parent)
    try:
        while dialog.run() == Gtk.ResponseType.OK:
            username, password = dialog.values()
            if not dialog.passwords_match():
                message(dialog, T("password_mismatch_title"), T("password_mismatch_body"), error=True)
                continue
            try:
                helper_call(
                    "change-credentials",
                    {"username": username, "password": password},
                    privileged=True,
                )
                return username
            except AppError as exc:
                message(dialog, T("account_change_failed"), str(exc), error=True)
        return None
    finally:
        dialog.destroy()


class MainWindow(Gtk.Window):
    def __init__(self, status: dict):
        super().__init__(title="Eduka-Block")
        self.status = status
        self.lock_requested = False
        self.restart_requested = False
        self.refreshing = False
        self.language_ready = False
        self.busy_active = False
        self.toast_timer = 0
        self.switching_page = False
        self.last_activity = time.monotonic()
        self.set_default_size(980, 660)
        self.set_size_request(760, 540)
        self.set_position(Gtk.WindowPosition.CENTER)
        add_classes(self, "eduka-window")
        if Path(ICON).exists():
            self.set_icon_from_file(ICON)
        self.connect("destroy", lambda *_: Gtk.main_level() and Gtk.main_quit())
        self.connect("delete-event", self.on_delete)
        self.connect("event", self.on_activity)
        self.connect("key-press-event", self.on_key_press)
        GLib.timeout_add_seconds(10, self.auto_lock_check)

        layout = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.add(layout)
        layout.pack_start(self.build_sidebar(), False, False, 0)

        overlay = Gtk.Overlay()
        layout.pack_start(overlay, True, True, 0)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(160)
        overlay.add(self.stack)
        for name, builder in (
            ("dashboard", self.build_dashboard),
            ("websites", self.build_websites),
            ("categories", self.build_categories),
            ("advanced", self.build_advanced),
        ):
            self.stack.add_named(self.page(builder()), name)
        overlay.add_overlay(self.build_toast())

        self.show_all()
        self.toast_revealer.set_reveal_child(False)
        self.load_status(status)
        self.language_ready = True
        self.select_page("dashboard")

    # ------------------------------------------------------------------ layout

    @staticmethod
    def page(content: Gtk.Widget) -> Gtk.Widget:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        add_classes(scroll, "page-scroll")
        add_classes(content, "page")
        scroll.add(content)
        return scroll

    @staticmethod
    def page_header(title_key: str, subtitle_key: str) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.pack_start(label(T(title_key), "page-title"), False, False, 0)
        box.pack_start(label(T(subtitle_key), "page-subtitle", wrap=True), False, False, 0)
        return box

    def build_sidebar(self) -> Gtk.Widget:
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        add_classes(sidebar, "sidebar")
        sidebar.set_size_request(208, -1)

        brand = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        add_classes(brand, "brand")
        brand.pack_start(logo_image(38), False, False, 0)
        names = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        names.set_valign(Gtk.Align.CENTER)
        names.pack_start(label("Eduka-Block", "brand-name"), False, False, 0)
        names.pack_start(label(T("brand_tagline", version=APP_VERSION), "brand-version"), False, False, 0)
        brand.pack_start(names, False, False, 0)
        sidebar.pack_start(brand, False, False, 0)

        self.nav_buttons: dict[str, Gtk.ToggleButton] = {}
        for name, label_key, icon_name in NAV_PAGES:
            nav = Gtk.ToggleButton()
            add_classes(nav, "nav-button")
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.pack_start(icon(icon_name, 16), False, False, 0)
            row.pack_start(Gtk.Label(label=T(label_key), xalign=0), True, True, 0)
            nav.add(row)
            nav.connect("toggled", self.on_nav_toggled, name)
            self.nav_buttons[name] = nav
            sidebar.pack_start(nav, False, False, 0)

        sidebar.pack_start(Gtk.Box(), True, True, 0)
        self.busy = Gtk.Spinner()
        add_classes(self.busy, "sidebar-spinner")
        sidebar.pack_start(self.busy, False, False, 0)
        self.busy_label = label("", "sidebar-note", wrap=True)
        sidebar.pack_start(self.busy_label, False, False, 0)

        self.language_combo = Gtk.ComboBoxText()
        for code, name in LANGUAGES.items():
            self.language_combo.append(code, name)
        self.language_combo.set_active_id(CURRENT_LANGUAGE)
        self.language_combo.set_tooltip_text(T("language"))
        self.language_combo.connect("changed", self.on_language_change)
        add_classes(self.language_combo, "sidebar-combo")
        sidebar.pack_start(self.language_combo, False, False, 0)
        self.lock_button = button(T("lock"), self.on_lock, "sidebar-lock", icon_name="system-lock-screen-symbolic")
        self.lock_button.set_tooltip_text(T("lock_tooltip"))
        sidebar.pack_start(self.lock_button, False, False, 0)
        return sidebar

    def build_toast(self) -> Gtk.Widget:
        self.toast_revealer = Gtk.Revealer()
        self.toast_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_UP)
        self.toast_revealer.set_halign(Gtk.Align.CENTER)
        self.toast_revealer.set_valign(Gtk.Align.END)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        add_classes(box, "toast")
        self.toast_icon = icon("emblem-ok-symbolic", 16)
        box.pack_start(self.toast_icon, False, False, 0)
        self.toast_label = label("", "toast-text")
        self.toast_label.set_max_width_chars(60)
        self.toast_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        box.pack_start(self.toast_label, False, False, 0)
        self.toast_revealer.add(box)
        self.toast_box = box
        return self.toast_revealer

    def build_dashboard(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)

        self.hero = card(0, "hero")
        hero_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        self.hero_icon = icon("security-high-symbolic", 56, "hero-icon")
        hero_row.pack_start(self.hero_icon, False, False, 0)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        texts.set_valign(Gtk.Align.CENTER)
        self.hero_title = label("", "hero-title", wrap=True)
        self.hero_subtitle = label("", "hero-subtitle", wrap=True)
        texts.pack_start(self.hero_title, False, False, 0)
        texts.pack_start(self.hero_subtitle, False, False, 0)
        hero_row.pack_start(texts, True, True, 0)
        self.recommended_button = button(
            T("turn_on_recommended"), self.on_recommended, "suggested-action", "hero-button",
            icon_name="security-high-symbolic",
        )
        self.recommended_button.set_halign(Gtk.Align.START)
        self.recommended_button.set_tooltip_text(T("recommended_tooltip"))
        texts.pack_start(self.recommended_button, False, False, 8)
        self.hero.pack_start(hero_row, False, False, 0)
        page.pack_start(self.hero, False, False, 0)

        layers = card(10)
        layers.pack_start(label(T("layers_title"), "card-title"), False, False, 0)
        grid = Gtk.Grid(column_spacing=12, row_spacing=8, column_homogeneous=True)
        self.layer_widgets: dict[str, tuple[Gtk.Image, Gtk.Label]] = {}
        for index, (key, _) in enumerate(protection_layers({})):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            add_classes(row, "layer")
            image = icon("emblem-ok-symbolic", 16)
            text = label(T(key), "layer-text")
            text.set_ellipsize(Pango.EllipsizeMode.END)
            row.pack_start(image, False, False, 0)
            row.pack_start(text, True, True, 0)
            grid.attach(row, index % 2, index // 2, 1, 1)
            self.layer_widgets[key] = (image, row)
        layers.pack_start(grid, False, False, 0)
        page.pack_start(layers, False, False, 0)

        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, homogeneous=True)
        self.stat_values: dict[str, Gtk.Label] = {}
        for key in ("stat_blocked", "stat_rules", "stat_ips", "stat_sync"):
            tile = card(2, "stat")
            value = label("0", "stat-value")
            value.set_ellipsize(Pango.EllipsizeMode.END)
            tile.pack_start(value, False, False, 0)
            tile.pack_start(label(T(key), "stat-label", wrap=True), False, False, 0)
            stats.pack_start(tile, True, True, 0)
            self.stat_values[key] = value
        page.pack_start(stats, False, False, 0)

        quick = card(10)
        quick.pack_start(label(T("quick_block_title"), "card-title"), False, False, 0)
        quick.pack_start(label(T("quick_block_text"), "card-text", wrap=True), False, False, 0)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.quick_entry = Gtk.Entry()
        self.quick_entry.set_placeholder_text(T("target_hint"))
        self.quick_entry.connect("activate", lambda *_: self.add_rule(self.quick_entry, "Manual"))
        row.pack_start(self.quick_entry, True, True, 0)
        row.pack_start(
            button(T("block_now"), lambda *_: self.add_rule(self.quick_entry, "Manual"),
                   "suggested-action", icon_name="list-add-symbolic"),
            False, False, 0,
        )
        quick.pack_start(row, False, False, 0)
        page.pack_start(quick, False, False, 0)
        return page

    def build_websites(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.pack_start(self.page_header("websites_title", "websites_subtitle"), False, False, 0)

        add = card(10)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.target_entry = Gtk.Entry()
        self.target_entry.set_placeholder_text(T("target_hint"))
        self.target_entry.connect("activate", lambda *_: self.add_rule(self.target_entry, None))
        row.pack_start(self.target_entry, True, True, 0)
        self.category = Gtk.ComboBoxText()
        for key in CATEGORIES:
            self.category.append(key, T(CATEGORY_KEYS[key]))
        self.category.set_active_id("Manual")
        row.pack_start(self.category, False, False, 0)
        row.pack_start(
            button(T("block_now"), lambda *_: self.add_rule(self.target_entry, None),
                   "suggested-action", icon_name="list-add-symbolic"),
            False, False, 0,
        )
        add.pack_start(row, False, False, 0)
        add.pack_start(label(T("add_help"), "card-text", wrap=True), False, False, 0)
        page.pack_start(add, False, False, 0)

        rules = card(10)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text(T("search_hint"))
        self.search.set_tooltip_text(T("search_shortcut"))
        self.search.connect("search-changed", self.on_search_changed)
        toolbar.pack_start(self.search, True, True, 0)
        toolbar.pack_start(button(T("import_action"), self.on_import, icon_name="document-open-symbolic"), False, False, 0)
        toolbar.pack_start(button(T("export_action"), self.on_export, icon_name="document-save-as-symbolic"), False, False, 0)
        self.remove_button = button(
            T("remove_selected"), self.on_remove, "destructive-action", icon_name="edit-delete-symbolic"
        )
        self.remove_button.set_sensitive(False)
        toolbar.pack_start(self.remove_button, False, False, 0)
        rules.pack_start(toolbar, False, False, 0)

        self.model = Gtk.ListStore(str, str, str, str, str, str, str)
        self.filter = self.model.filter_new()
        self.filter.set_visible_func(self.filter_visible)
        self.sorted = Gtk.TreeModelSort(model=self.filter)
        self.sorted.set_sort_column_id(COL_TARGET, Gtk.SortType.ASCENDING)
        self.tree = Gtk.TreeView(model=self.sorted)
        self.tree.set_enable_search(False)
        self.tree.set_rubber_banding(True)
        self.tree.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.tree.get_selection().connect("changed", self.on_selection_changed)
        self.tree.connect("key-press-event", self.on_tree_key)
        blocked_renderer = Gtk.CellRendererText(weight=Pango.Weight.BOLD, foreground="#dc2626")
        blocked_column = Gtk.TreeViewColumn(T("column_status"), blocked_renderer, text=COL_STATUS)
        self.tree.append_column(blocked_column)
        for title_key, column, expand in [
            ("column_target", COL_TARGET, True),
            # Type is implied by Coverage and still searchable; the table
            # must fit next to the sidebar at the minimum window width.
            ("column_category", COL_CATEGORY, False),
            ("column_coverage", COL_COVERAGE, True),
            ("column_added", COL_ADDED, False),
        ]:
            renderer = Gtk.CellRendererText()
            renderer.set_padding(6, 6)
            if expand:
                # Ellipsized cells otherwise request their full natural width.
                renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
                renderer.set_property("width-chars", 16)
            tree_column = Gtk.TreeViewColumn(T(title_key), renderer, text=column)
            tree_column.set_expand(expand)
            tree_column.set_resizable(True)
            tree_column.set_sort_column_id(column)
            self.tree.append_column(tree_column)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(260)
        add_classes(scroll, "list-frame")
        scroll.add(self.tree)
        rules.pack_start(scroll, True, True, 0)
        self.list_summary = label("", "card-text")
        rules.pack_start(self.list_summary, False, False, 0)
        page.pack_start(rules, True, True, 0)
        return page

    def build_categories(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.pack_start(self.page_header("categories_title", "categories_subtitle"), False, False, 0)

        lists = card(0, "list-card")
        self.list_switches: dict[str, Gtk.Switch] = {}
        self.list_details: dict[str, Gtk.Label] = {}
        for index, (key, icon_name) in enumerate(LIST_ROWS):
            if index:
                lists.pack_start(Gtk.Separator(), False, False, 0)
            switch, detail = self.toggle_row(
                lists, icon_name, f"list_{key}_title", f"list_{key}_text", self.on_list_toggle, key
            )
            self.list_switches[key] = switch
            self.list_details[key] = detail
        page.pack_start(lists, False, False, 0)

        strict = card(0, "list-card")
        self.strict_switch, self.strict_detail = self.toggle_row(
            strict, "channel-secure-symbolic", "strict_title", "strict_text", self.on_strict_toggle, None
        )
        page.pack_start(strict, False, False, 0)

        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        footer.pack_start(label(T("lists_auto_update"), "card-text", wrap=True), True, True, 0)
        self.update_lists_button = button(T("update_lists"), self.on_update_lists, icon_name="view-refresh-symbolic")
        footer.pack_end(self.update_lists_button, False, False, 0)
        page.pack_start(footer, False, False, 0)
        page.pack_start(label(T("lists_source"), "fine-print", wrap=True), False, False, 0)
        return page

    def toggle_row(self, parent: Gtk.Box, icon_name: str, title_key: str, text_key: str, callback, data):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        add_classes(row, "toggle-row")
        badge = Gtk.Box()
        add_classes(badge, "row-icon")
        badge.set_valign(Gtk.Align.CENTER)
        badge.pack_start(icon(icon_name, 20), True, True, 0)
        row.pack_start(badge, False, False, 0)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        texts.set_valign(Gtk.Align.CENTER)
        texts.pack_start(label(T(title_key), "row-title"), False, False, 0)
        texts.pack_start(label(T(text_key), "row-text", wrap=True), False, False, 0)
        detail = label("", "row-detail")
        texts.pack_start(detail, False, False, 0)
        row.pack_start(texts, True, True, 0)
        switch = Gtk.Switch()
        switch.set_valign(Gtk.Align.CENTER)
        switch.connect("state-set", callback, data)
        row.pack_end(switch, False, False, 0)
        parent.pack_start(row, False, False, 0)
        return switch, detail

    def build_advanced(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        page.pack_start(self.page_header("advanced_title", "advanced_subtitle"), False, False, 0)

        smart = card(0, "list-card")
        self.smart_switch, self.smart_detail = self.toggle_row(
            smart, "view-refresh-symbolic", "smart_tracking", "smart_tracking_tip", self.on_smart_default, None
        )
        sync_switch(self.smart_switch, True)
        sync_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        add_classes(sync_row, "row-actions")
        self.dns_status = label("", "pill")
        sync_row.pack_start(self.dns_status, False, False, 0)
        sync_row.pack_end(button(T("sync_now"), self.on_sync_now, icon_name="view-refresh-symbolic"), False, False, 0)
        smart.pack_start(sync_row, False, False, 0)
        page.pack_start(smart, False, False, 0)

        squid = card(10)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        texts.pack_start(label(T("squid_title"), "card-title"), False, False, 0)
        self.squid_status = label("", "pill")
        self.squid_status.set_halign(Gtk.Align.START)
        texts.pack_start(self.squid_status, False, False, 0)
        head.pack_start(texts, True, True, 0)
        self.squid_switch = Gtk.Switch()
        self.squid_switch.set_valign(Gtk.Align.CENTER)
        self.squid_switch.connect("state-set", self.on_squid_toggle)
        head.pack_end(self.squid_switch, False, False, 0)
        squid.pack_start(head, False, False, 0)
        squid.pack_start(label(T("squid_description"), "card-text", wrap=True), False, False, 0)
        commands = label(T("squid_commands"), "code-box")
        commands.set_selectable(True)
        squid.pack_start(commands, False, False, 0)
        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.squid_keyword_entry = Gtk.Entry()
        self.squid_keyword_entry.set_placeholder_text(T("squid_keyword_hint"))
        self.squid_keyword_entry.connect("activate", self.on_squid_add_keyword)
        add_row.pack_start(self.squid_keyword_entry, True, True, 0)
        add_row.pack_start(button(T("squid_add_keyword"), self.on_squid_add_keyword, icon_name="list-add-symbolic"), False, False, 0)
        squid.pack_start(add_row, False, False, 0)
        self.squid_flow = Gtk.FlowBox()
        self.squid_flow.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.squid_flow.set_max_children_per_line(12)
        self.squid_flow.set_row_spacing(6)
        self.squid_flow.set_column_spacing(6)
        squid.pack_start(self.squid_flow, False, False, 0)
        remove_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.squid_count = label("", "card-text")
        remove_row.pack_start(self.squid_count, True, True, 0)
        remove_row.pack_end(
            button(T("squid_remove_keyword"), self.on_squid_remove_keyword, "destructive-action",
                   icon_name="edit-delete-symbolic"),
            False, False, 0,
        )
        squid.pack_start(remove_row, False, False, 0)
        page.pack_start(squid, False, False, 0)

        account = card(10)
        account_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        account_texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        account_texts.pack_start(label(T("account_title"), "card-title"), False, False, 0)
        account_texts.pack_start(label(T("account_text"), "card-text", wrap=True), False, False, 0)
        account_row.pack_start(account_texts, True, True, 0)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_valign(Gtk.Align.CENTER)
        actions.pack_start(button(T("change_account"), self.on_change_account, icon_name="avatar-default-symbolic"), False, False, 0)
        actions.pack_start(button(T("about"), self.on_about, icon_name="help-about-symbolic"), False, False, 0)
        account_row.pack_end(actions, False, False, 0)
        account.pack_start(account_row, False, False, 0)
        page.pack_start(account, False, False, 0)
        page.pack_start(label(T("browser_note"), "fine-print", wrap=True), False, False, 0)
        return page

    # ------------------------------------------------------------------ state

    def filter_visible(self, model, tree_iter, _data=None) -> bool:
        query = self.search.get_text().strip().lower() if hasattr(self, "search") else ""
        return not query or any(
            query in str(model[tree_iter][column]).lower()
            for column in (COL_TARGET, COL_TYPE, COL_CATEGORY, COL_COVERAGE)
        )

    def load_status(self, status: dict) -> None:
        self.status = status
        self.load_rules(status)
        self.load_dashboard(status)
        self.load_categories(status)
        self.load_advanced(status)

    def load_rules(self, status: dict) -> None:
        self.model.clear()
        for entry in status.get("entries", []):
            kind = entry.get("kind", "")
            ip_count = len(entry.get("resolved_ips", []))
            coverage = (
                T("coverage_domain_smart", count=ip_count)
                if kind == "domain" and entry.get("smart")
                else T("coverage_domain_dns")
                if kind == "domain"
                else T("coverage_firewall")
            )
            self.model.append(
                [
                    str(entry.get("id", "")),
                    T("blocked_status"),
                    str(entry.get("value", "")),
                    T(TYPE_KEYS.get(kind, kind)),
                    T(CATEGORY_KEYS.get(entry.get("category"), "category_other")),
                    coverage,
                    str(entry.get("created_at", ""))[:10],
                ]
            )
        self.update_list_summary()
        self.on_selection_changed()

    def load_dashboard(self, status: dict) -> None:
        layers = protection_layers(status)
        active = sum(1 for _, on in layers if on)
        if active == len(layers):
            state, title, icon_name = "ok", "hero_strong", "security-high-symbolic"
        elif active >= 3:
            state, title, icon_name = "warning", "hero_partial", "security-medium-symbolic"
        else:
            state, title, icon_name = "error", "hero_weak", "security-low-symbolic"
        context = self.hero.get_style_context()
        for name in ("hero-ok", "hero-warning", "hero-error"):
            context.remove_class(name)
        context.add_class(f"hero-{state}")
        self.hero_icon.set_from_icon_name(icon_name, Gtk.IconSize.BUTTON)
        self.hero_title.set_text(T(title))
        self.hero_subtitle.set_text(T("hero_layers", active=active, total=len(layers)))
        self.recommended_button.set_visible(not recommended_active(status))
        for key, on in layers:
            image, row = self.layer_widgets[key]
            image.set_from_icon_name("emblem-ok-symbolic" if on else "window-close-symbolic", Gtk.IconSize.BUTTON)
            row_context = row.get_style_context()
            row_context.remove_class("layer-on")
            row_context.remove_class("layer-off")
            row_context.add_class("layer-on" if on else "layer-off")

        self.stat_values["stat_blocked"].set_text(f"{int(status.get('total_count', 0)):,}")
        self.stat_values["stat_rules"].set_text(f"{int(status.get('manual_count', 0)):,}")
        self.stat_values["stat_ips"].set_text(f"{int(status.get('tracked_ip_count', 0)):,}")
        last_sync = local_time(status.get("smart_sync", {}).get("last_run"))
        self.stat_values["stat_sync"].set_text(short_time(status.get("smart_sync", {}).get("last_run")))
        self.stat_values["stat_sync"].set_tooltip_text(last_sync or T("sync_never"))

    def load_categories(self, status: dict) -> None:
        self.refreshing = True
        lists = status.get("lists", {})
        any_enabled = False
        for key, _ in LIST_ROWS:
            settings = lists.get(key, {})
            enabled = bool(settings.get("enabled"))
            any_enabled = any_enabled or enabled
            sync_switch(self.list_switches[key], enabled)
            if enabled:
                updated = local_time(settings.get("updated_at"))[:10]
                self.list_details[key].set_text(
                    T("list_on", count=f"{int(settings.get('domain_count', 0)):,}", date=updated)
                )
                set_state_class(self.list_details[key], "ok")
            else:
                self.list_details[key].set_text(T("list_off"))
                set_state_class(self.list_details[key], "warning")
        strict = bool(status.get("strict_mode", {}).get("enabled"))
        sync_switch(self.strict_switch, strict)
        self.strict_detail.set_text(T("strict_on") if strict else T("strict_off"))
        set_state_class(self.strict_detail, "ok" if strict else "warning")
        self.update_lists_button.set_sensitive(any_enabled)
        self.refreshing = False

    def load_advanced(self, status: dict) -> None:
        self.refreshing = True
        dns_engine = bool(status.get("dns_engine"))
        self.dns_status.set_text(T("dns_active" if dns_engine else "dns_fallback"))
        set_state_class(self.dns_status, "ok" if dns_engine else "warning")
        last_sync = local_time(status.get("smart_sync", {}).get("last_run"))
        self.smart_detail.set_text(T("sync_last", date=last_sync) if last_sync else T("sync_never"))

        squid = status.get("squid_proxy", {})
        for child in self.squid_flow.get_children():
            self.squid_flow.remove(child)
        keywords = [str(keyword) for keyword in squid.get("keywords", [])]
        for keyword in keywords:
            chip = label(keyword, "chip", xalign=0.5)
            self.squid_flow.add(chip)
        self.squid_flow.show_all()
        self.squid_count.set_text(T("squid_keyword_count", count=len(keywords)))
        squid_enabled = bool(squid.get("enabled"))
        squid_running = bool(squid.get("running"))
        squid_installed = bool(squid.get("installed"))
        if squid_enabled and squid_running:
            squid_text, squid_state = "squid_status_on", "ok"
        elif squid_enabled:
            squid_text, squid_state = "squid_status_stopped", "warning"
        elif squid_installed:
            squid_text, squid_state = "squid_status_off", "warning"
        else:
            squid_text, squid_state = "squid_status_missing", "error"
        self.squid_status.set_text(T(squid_text))
        set_state_class(self.squid_status, squid_state)
        sync_switch(self.squid_switch, squid_enabled)
        self.squid_switch.set_sensitive(squid_installed or squid_enabled)
        self.refreshing = False

    def update_list_summary(self) -> None:
        total = len(self.model)
        shown = len(self.filter)
        if total == 0:
            text = T("no_rules")
        elif shown == total:
            text = T("rules_shown_all", count=total)
        else:
            text = T("rules_shown_filtered", shown=shown, count=total)
        self.list_summary.set_text(text)

    def select_page(self, name: str) -> None:
        self.nav_buttons[name].set_active(True)

    def on_nav_toggled(self, nav: Gtk.ToggleButton, name: str) -> None:
        if self.switching_page:
            return
        self.switching_page = True
        # Exactly one page is selected; clicking the current page keeps it on.
        for other, other_button in self.nav_buttons.items():
            other_button.set_active(other == name)
        self.switching_page = False
        self.stack.set_visible_child_name(name)
        if name == "websites":
            self.target_entry.grab_focus()
        elif name == "dashboard":
            self.quick_entry.grab_focus()

    def show_toast(self, text: str, state: str = "ok") -> None:
        self.toast_label.set_text(text)
        self.toast_icon.set_from_icon_name(
            {"ok": "emblem-ok-symbolic", "warning": "dialog-warning-symbolic"}.get(state, "dialog-error-symbolic"),
            Gtk.IconSize.BUTTON,
        )
        context = self.toast_box.get_style_context()
        for name in ("toast-ok", "toast-warning", "toast-error"):
            context.remove_class(name)
        context.add_class(f"toast-{state}")
        self.toast_revealer.set_reveal_child(True)
        if self.toast_timer:
            GLib.source_remove(self.toast_timer)

        def hide() -> bool:
            self.toast_revealer.set_reveal_child(False)
            self.toast_timer = 0
            return False

        self.toast_timer = GLib.timeout_add_seconds(TOAST_SECONDS, hide)

    def set_busy(self, active: bool, text: str = "") -> None:
        self.busy_active = active
        self.stack.set_sensitive(not active)
        for widget in (*self.nav_buttons.values(), self.language_combo, self.lock_button):
            widget.set_sensitive(not active)
        self.busy.start() if active else self.busy.stop()
        self.busy_label.set_text(text if active else "")
        if not active:
            self.last_activity = time.monotonic()

    def run_helper(
        self,
        action: str,
        payload: dict | None,
        busy_key: str,
        done_key: str,
        failure_title_key: str,
        on_success=None,
    ) -> None:
        """Run a privileged helper action without freezing the interface."""
        self.set_busy(True, T(busy_key))

        def done(result, error) -> bool:
            self.set_busy(False)
            if error:
                self.show_toast(T("operation_failed"), "error")
                message(self, T(failure_title_key), error, error=True)
                try:
                    self.load_status(helper_call("status"))
                except AppError:
                    self.load_status(self.status)
            else:
                self.load_status(result)
                self.show_toast(T(done_key))
                if on_success:
                    on_success(result)
            return False

        def worker() -> None:
            try:
                GLib.idle_add(done, helper_call(action, payload, privileged=True), None)
            except AppError as exc:
                GLib.idle_add(done, None, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ protection

    def configure(self, payload: dict, busy_key: str = "applying") -> None:
        needs_download = any(payload.get("lists", {}).values()) or payload.get("refresh")
        self.run_helper(
            "protection-configure",
            payload,
            "downloading" if needs_download else busy_key,
            "protection_updated",
            "protection_failed_title",
        )

    def on_recommended(self, *_args) -> None:
        if confirm(self, T("recommended_confirm_title"), T("recommended_confirm_body"), "turn_on"):
            self.configure({"lists": {key: True for key in RECOMMENDED_LISTS}, "strict": True})

    def on_list_toggle(self, switch: Gtk.Switch, requested: bool, key: str) -> bool:
        if self.refreshing:
            return False
        self.configure({"lists": {key: requested}})
        return True  # The switch moves when the helper reports the new state.

    def on_strict_toggle(self, switch: Gtk.Switch, requested: bool, _data) -> bool:
        if self.refreshing:
            return False
        if not requested and not confirm(self, T("strict_disable_title"), T("strict_disable_body"), "turn_off"):
            self.refreshing = True
            sync_switch(switch, True)
            self.refreshing = False
            return True
        self.configure({"strict": requested})
        return True

    def on_update_lists(self, *_args) -> None:
        self.configure({"refresh": True})

    def on_smart_default(self, switch: Gtk.Switch, requested: bool, _data) -> bool:
        return False  # Local preference for new rules; nothing to apply.

    # ------------------------------------------------------------------ rules

    def add_rule(self, entry: Gtk.Entry, category: str | None) -> None:
        raw = entry.get_text()
        if not raw.strip():
            entry.grab_focus()
            return
        try:
            rule_target(raw)
        except ValidationError as exc:
            message(self, T("invalid_target_title"), T(exc.code), error=True)
            return
        self.run_helper(
            "add",
            {
                "target": raw,
                "category": category or self.category.get_active_id() or "Manual",
                "smart": self.smart_switch.get_active(),
            },
            "applying",
            "applied",
            "add_failed_title",
            on_success=lambda _result: entry.set_text(""),
        )

    def selected_rules(self) -> list[tuple[str, str]]:
        model, paths = self.tree.get_selection().get_selected_rows()
        return [(model[path][COL_ID], model[path][COL_TARGET]) for path in paths]

    def on_selection_changed(self, *_args) -> None:
        self.remove_button.set_sensitive(bool(self.selected_rules()))

    def on_search_changed(self, *_args) -> None:
        self.filter.refilter()
        self.update_list_summary()

    def on_remove(self, *_args) -> None:
        selected = self.selected_rules()
        if not selected:
            return
        if len(selected) == 1:
            body = T("confirm_remove_body", target=selected[0][1])
        else:
            body = T("confirm_remove_many_body", count=len(selected))
        if not confirm(self, T("confirm_remove_title"), body, "remove"):
            return
        self.run_helper(
            "remove", {"ids": [entry_id for entry_id, _ in selected]},
            "removing", "removed", "remove_failed_title",
        )

    def on_tree_key(self, _widget, event) -> bool:
        if event.keyval == Gdk.KEY_Delete:
            self.on_remove()
            return True
        return False

    def on_import(self, *_args) -> None:
        chooser = Gtk.FileChooserNative.new(
            T("import_rules"), self, Gtk.FileChooserAction.OPEN, T("import_action"), T("cancel")
        )
        text_filter = Gtk.FileFilter()
        text_filter.set_name(T("text_files"))
        text_filter.add_mime_type("text/plain")
        text_filter.add_pattern("*.txt")
        text_filter.add_pattern("hosts")
        chooser.add_filter(text_filter)
        response = chooser.run()
        path = chooser.get_filename()
        chooser.destroy()
        if response != Gtk.ResponseType.ACCEPT or not path:
            return
        try:
            with open(path, "rb") as stream:
                data = stream.read(MAX_IMPORT_FILE_BYTES + 1)
            if len(data) > MAX_IMPORT_FILE_BYTES:
                raise ValueError("too large")
            text = data.decode("utf-8")
        except (OSError, ValueError):
            message(self, T("import_failed_title"), T("file_read_failed"), error=True)
            return
        items = parse_rules_text(text, self.category.get_active_id() or "Manual")
        if not items:
            message(self, T("import_failed_title"), T("err_import_empty"), error=True)
            return
        if len(items) > MAX_IMPORT_ITEMS:
            message(self, T("import_failed_title"), T("err_import_large"), error=True)
            return
        if not confirm(self, T("import_confirm_title", count=len(items)), T("import_confirm_body"), "import_action"):
            return

        def summary(result: dict) -> None:
            counts = result.get("import_result", {})
            self.show_toast(
                T(
                    "import_done_body",
                    added=counts.get("added", 0),
                    skipped=counts.get("skipped", 0),
                    invalid=counts.get("invalid", 0),
                )
            )

        self.run_helper(
            "import",
            {"items": items, "smart": self.smart_switch.get_active()},
            "importing",
            "applied",
            "import_failed_title",
            on_success=summary,
        )

    def on_export(self, *_args) -> None:
        entries = self.status.get("entries", [])
        if not entries:
            self.show_toast(T("no_rules"), "warning")
            return
        chooser = Gtk.FileChooserNative.new(
            T("export_rules"), self, Gtk.FileChooserAction.SAVE, T("export_action"), T("cancel")
        )
        chooser.set_do_overwrite_confirmation(True)
        chooser.set_current_name("eduka-block-rules.txt")
        response = chooser.run()
        path = chooser.get_filename()
        chooser.destroy()
        if response != Gtk.ResponseType.ACCEPT or not path:
            return
        try:
            Path(path).write_text(export_rules_text(entries), encoding="utf-8")
        except OSError as exc:
            message(self, T("export_failed_title"), str(exc), error=True)
            return
        self.show_toast(T("export_done_body", count=len(entries), path=path))

    def on_sync_now(self, *_args) -> None:
        self.run_helper("sync-smart-ips", None, "syncing", "synced", "sync_failed_title")

    # ------------------------------------------------------------------ squid

    def current_squid_keywords(self) -> list[str]:
        return [str(keyword) for keyword in self.status.get("squid_proxy", {}).get("keywords", [])]

    def on_squid_toggle(self, switch: Gtk.Switch, requested: bool) -> bool:
        if self.refreshing:
            return False
        if not confirm(
            self,
            T("squid_enable_title" if requested else "squid_disable_title"),
            T("squid_enable_body" if requested else "squid_disable_body"),
        ):
            self.refreshing = True
            sync_switch(switch, not requested)
            self.refreshing = False
            return True
        self.run_squid_update(requested, self.current_squid_keywords())
        return True

    def on_squid_add_keyword(self, *_args) -> None:
        keyword = " ".join(self.squid_keyword_entry.get_text().strip().lower().split())
        if not keyword:
            self.squid_keyword_entry.grab_focus()
            return
        keywords = self.current_squid_keywords()
        if keyword in keywords:
            self.show_toast(T("squid_keyword_exists", keyword=keyword), "warning")
            return
        keywords.append(keyword)
        enabled = bool(self.status.get("squid_proxy", {}).get("enabled"))
        self.run_squid_update(enabled, keywords, clear_entry=True)

    def on_squid_remove_keyword(self, *_args) -> None:
        selected = self.squid_flow.get_selected_children()
        if not selected:
            self.show_toast(T("squid_select_body"), "warning")
            return
        keyword = selected[0].get_child().get_text()
        keywords = [item for item in self.current_squid_keywords() if item != keyword]
        if not keywords:
            message(self, T("squid_invalid_title"), T("err_squid_keywords_limit"), error=True)
            return
        enabled = bool(self.status.get("squid_proxy", {}).get("enabled"))
        self.run_squid_update(enabled, keywords)

    def run_squid_update(self, enabled: bool, keywords: list[str], clear_entry: bool = False) -> None:
        self.run_helper(
            "squid-configure",
            {"enabled": enabled, "keywords": keywords},
            "squid_working",
            "squid_applied",
            "squid_failed_title",
            on_success=(lambda _result: self.squid_keyword_entry.set_text("")) if clear_entry else None,
        )

    # ------------------------------------------------------------------ misc

    def on_change_account(self, *_args) -> None:
        if run_account_change(self):
            self.show_toast(T("account_changed_title"))

    def on_about(self, *_args) -> None:
        dialog = Gtk.AboutDialog(transient_for=self, modal=True)
        dialog.set_program_name("Eduka-Block")
        dialog.set_version(APP_VERSION)
        dialog.set_comments(T("about_text"))
        dialog.set_website("https://edukasaunos.tl")
        dialog.set_website_label("Edukasaun OS")
        dialog.set_authors(["STI-MCAS & IDEA", "Developer: Hugo Moniz do Rego"])
        dialog.set_license_type(Gtk.License.GPL_3_0)
        dialog.set_logo_icon_name("eduka-block")
        dialog.run()
        dialog.destroy()

    def on_language_change(self, combo: Gtk.ComboBoxText) -> None:
        if not self.language_ready or self.busy_active:
            return
        code = combo.get_active_id()
        if code and code != CURRENT_LANGUAGE:
            set_language(code)
            self.restart_requested = True
            self.destroy()

    def on_key_press(self, _widget, event) -> bool:
        if not event.state & Gdk.ModifierType.CONTROL_MASK:
            return False
        key = Gdk.keyval_to_lower(event.keyval)
        if key == Gdk.KEY_f:
            self.select_page("websites")
            self.search.grab_focus()
            return True
        if key == Gdk.KEY_l:
            self.on_lock()
            return True
        return False

    def on_activity(self, *_args) -> bool:
        self.last_activity = time.monotonic()
        return False

    def on_delete(self, *_args) -> bool:
        # Closing mid-operation would drop the result of a privileged change.
        return self.busy_active

    def auto_lock_check(self) -> bool:
        if not self.get_visible():
            return False
        if self.busy_active:
            return True
        if time.monotonic() - self.last_activity >= AUTO_LOCK_SECONDS:
            self.on_lock()
            return False
        return True

    def on_lock(self, *_args) -> None:
        if self.busy_active:
            return
        self.lock_requested = True
        self.destroy()


def create_first_account() -> dict | None:
    dialog = AccountDialog("setup")
    try:
        while True:
            if dialog.run() != Gtk.ResponseType.OK:
                return None
            username, password = dialog.values()
            if not dialog.passwords_match():
                message(dialog, T("password_mismatch_title"), T("password_mismatch_body"), error=True)
                continue
            try:
                status = helper_call(
                    "setup", {"username": username, "password": password}, privileged=True
                )
                break
            except AppError as exc:
                message(dialog, T("account_create_failed"), str(exc), error=True)
    finally:
        dialog.destroy()
    message(None, T("account_created_title"), T("account_created_body"))
    return status


def authenticate() -> dict | None:
    try:
        status = helper_call("status")
    except AppError as exc:
        message(None, T("startup_failed_title"), str(exc), error=True)
        return None
    if not status.get("configured") and create_first_account() is None:
        return None

    dialog = AccountDialog("login")
    attempts = 0
    while True:
        response = dialog.run()
        if response in {Gtk.ResponseType.CANCEL, Gtk.ResponseType.DELETE_EVENT}:
            dialog.destroy()
            return None
        if response not in {Gtk.ResponseType.OK, RESPONSE_CHANGE_ACCOUNT}:
            continue
        username, password = dialog.values()
        # PBKDF2 takes a moment; show a busy cursor instead of a frozen dialog.
        window = dialog.get_window()
        if window:
            window.set_cursor(Gdk.Cursor.new_from_name(dialog.get_display(), "wait"))
        while Gtk.events_pending():
            Gtk.main_iteration()
        valid = verify_credentials(username, password, CREDENTIALS_PATH)
        if window:
            window.set_cursor(None)
        if not valid:
            attempts += 1
            dialog.password.set_text("")
            remaining = MAX_LOGIN_ATTEMPTS - attempts
            if remaining <= 0:
                dialog.destroy()
                message(None, T("too_many_title"), T("too_many_body"), error=True)
                return None
            message(
                dialog,
                T("login_failed_title"),
                T("login_failed_body") + "\n" + T("attempts_left", count=remaining),
                error=True,
            )
            dialog.password.grab_focus()
            continue
        if response == RESPONSE_CHANGE_ACCOUNT:
            dialog.hide()
            changed_username = run_account_change(None)
            dialog.show_all()
            dialog.password.set_text("")
            if changed_username:
                dialog.username.set_text(changed_username)
                message(dialog, T("account_changed_title"), T("account_changed_body"))
            dialog.password.grab_focus()
            continue
        dialog.destroy()
        try:
            return helper_call("status")
        except AppError as exc:
            message(None, T("startup_failed_title"), str(exc), error=True)
            return None


def main() -> int:
    load_css()
    while True:
        status = authenticate()
        if status is None:
            return 0
        while True:
            window = MainWindow(status)
            Gtk.main()
            if window.restart_requested:
                try:
                    status = helper_call("status")
                except AppError as exc:
                    message(None, T("startup_failed_title"), str(exc), error=True)
                    return 1
                continue
            break
        if not window.lock_requested:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
