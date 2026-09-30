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
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402


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
    normalize_target,
    parse_rules_text,
    verify_credentials,
)
from eduka_block_i18n import LANGUAGES, load_language, save_language, tr  # noqa: E402


HELPER = "/usr/lib/eduka-block/eduka-block-helper"
ICON = "/usr/share/icons/hicolor/scalable/apps/eduka-block.svg"
CSS = "/usr/share/eduka-block/eduka-block.css"
CONFIG_PATH = Path.home() / ".config" / "eduka-block" / "settings.json"
AUTO_LOCK_SECONDS = 600
MAX_LOGIN_ATTEMPTS = 5
MAX_IMPORT_ITEMS = 1000
MAX_IMPORT_FILE_BYTES = 2 * 1024 * 1024
RESPONSE_CHANGE_ACCOUNT = 1001
CURRENT_LANGUAGE = load_language(CONFIG_PATH)

# Seconds allowed per helper action. The helper may wait up to 90 s for the
# system lock, so every timeout leaves room for that plus the work itself.
HELPER_TIMEOUTS = {
    "status": 30,
    "adult-enable": 300,
    "adult-update": 300,
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


def confirm(parent: Gtk.Window, title: str, body: str) -> bool:
    dialog = Gtk.MessageDialog(
        transient_for=parent,
        modal=True,
        message_type=Gtk.MessageType.QUESTION,
        buttons=Gtk.ButtonsType.CANCEL,
        text=title,
    )
    dialog.format_secondary_text(body)
    dialog.add_button(T("continue"), Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    result = dialog.run() == Gtk.ResponseType.OK
    dialog.destroy()
    return result


def section_title(key: str) -> Gtk.Label:
    title = Gtk.Label(xalign=0)
    title.set_ellipsize(Pango.EllipsizeMode.END)
    title.set_markup(f"<b>{GLib.markup_escape_text(T(key))}</b>")
    title.get_style_context().add_class("section-title")
    return title


def icon_button(icon: str, tooltip_key: str, callback) -> Gtk.Button:
    button = Gtk.Button.new_from_icon_name(icon, Gtk.IconSize.BUTTON)
    button.set_tooltip_text(T(tooltip_key))
    button.connect("clicked", callback)
    return button


class AccountDialog(Gtk.Dialog):
    """Login ("login"), first-run ("setup") or account replacement ("change")."""

    def __init__(self, mode: str, parent: Gtk.Window | None = None):
        super().__init__(transient_for=parent, modal=True)
        self.mode = mode
        self.setup = mode != "login"
        self.set_default_size(430, 370 if self.setup else 300)
        self.set_resizable(False)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.get_style_context().add_class("auth-dialog")
        self.cancel_button = self.add_button("", Gtk.ResponseType.CANCEL)
        self.change_button = None
        if mode == "login":
            self.change_button = self.add_button("", RESPONSE_CHANGE_ACCOUNT)
        self.action_button = self.add_button("", Gtk.ResponseType.OK)
        self.action_button.get_style_context().add_class("suggested-action")
        self.set_default_response(Gtk.ResponseType.OK)

        box = self.get_content_area()
        box.set_spacing(9)
        box.set_border_width(16)
        box.get_style_context().add_class("auth-panel")
        shield = Gtk.Image.new_from_icon_name("security-high-symbolic", Gtk.IconSize.DIALOG)
        shield.set_pixel_size(30)
        shield.get_style_context().add_class("auth-icon")
        box.pack_start(shield, False, False, 0)
        self.heading = Gtk.Label()
        self.heading.set_xalign(0.5)
        self.heading.get_style_context().add_class("boxed-heading")
        box.pack_start(self.heading, False, False, 0)
        self.note = Gtk.Label()
        self.note.set_line_wrap(True)
        self.note.set_max_width_chars(48)
        self.note.set_justify(Gtk.Justification.CENTER)
        self.note.get_style_context().add_class("info-box")
        box.pack_start(self.note, False, False, 0)

        grid = Gtk.Grid(column_spacing=9, row_spacing=8)
        grid.set_border_width(8)
        grid.get_style_context().add_class("form-box")
        box.pack_start(grid, False, False, 0)
        self.language_label = Gtk.Label(xalign=0)
        self.language_label.get_style_context().add_class("field-label")
        grid.attach(self.language_label, 0, 0, 1, 1)
        self.language_combo = Gtk.ComboBoxText()
        self.language_combo.set_hexpand(True)
        for code, name in LANGUAGES.items():
            self.language_combo.append(code, name)
        self.language_combo.set_active_id(CURRENT_LANGUAGE)
        self.language_combo.connect("changed", self.on_language)
        grid.attach(self.language_combo, 1, 0, 1, 1)
        self.username_label = Gtk.Label(xalign=0)
        self.username_label.get_style_context().add_class("field-label")
        grid.attach(self.username_label, 0, 1, 1, 1)
        self.username = Gtk.Entry()
        self.username.set_activates_default(True)
        grid.attach(self.username, 1, 1, 1, 1)
        self.password_label = Gtk.Label(xalign=0)
        self.password_label.get_style_context().add_class("field-label")
        grid.attach(self.password_label, 0, 2, 1, 1)
        self.password = self.password_entry()
        grid.attach(self.password, 1, 2, 1, 1)
        self.confirm_label = None
        self.confirm_password = None
        self.password_status = None
        if self.setup:
            self.confirm_label = Gtk.Label(xalign=0)
            self.confirm_label.get_style_context().add_class("field-label")
            grid.attach(self.confirm_label, 0, 3, 1, 1)
            self.confirm_password = self.password_entry()
            grid.attach(self.confirm_password, 1, 3, 1, 1)
            self.password_status = Gtk.Label(xalign=0)
            self.password_status.set_line_wrap(True)
            self.password_status.get_style_context().add_class("password-status")
            grid.attach(self.password_status, 0, 4, 2, 1)
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
        headings = {
            "setup": "protect_settings",
            "login": "manager_authorization",
            "change": "change_account_title",
        }
        notes = {"setup": "setup_note", "login": "login_note", "change": "change_account_note"}
        actions = {"setup": "create_account", "login": "sign_in", "change": "save_account"}
        self.set_title(T(titles[self.mode]))
        self.cancel_button.set_label(T("cancel"))
        self.action_button.set_label(T(actions[self.mode]))
        if self.change_button:
            self.change_button.set_label(T("change_account"))
        self.heading.set_markup(
            "<span size='large' weight='bold'>"
            + GLib.markup_escape_text(T(headings[self.mode]))
            + "</span>"
        )
        self.note.set_text(T(notes[self.mode]))
        self.language_label.set_text(T("language"))
        self.username_label.set_text(T("username"))
        self.username.set_placeholder_text(T("username_hint"))
        self.password_label.set_text(T("password"))
        self.password.set_placeholder_text(T("password_minimum"))
        self.password.set_icon_tooltip_text(Gtk.EntryIconPosition.SECONDARY, T("show_password"))
        if self.confirm_label:
            self.confirm_label.set_text(T("repeat_password"))
            self.confirm_password.set_placeholder_text(T("repeat_password"))
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
        super().__init__(title=f"Eduka-Block {APP_VERSION}")
        self.status = status
        self.lock_requested = False
        self.restart_requested = False
        self.refreshing = False
        self.language_ready = False
        self.busy_active = False
        self.last_activity = time.monotonic()
        self.set_default_size(900, 600)
        self.set_size_request(700, 500)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.get_style_context().add_class("eduka-window")
        if Path(ICON).exists():
            self.set_icon_from_file(ICON)
        self.connect("destroy", lambda *_: Gtk.main_quit())
        self.connect("delete-event", self.on_delete)
        self.connect("event", self.on_activity)
        self.connect("key-press-event", self.on_key_press)
        GLib.timeout_add_seconds(10, self.auto_lock_check)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(outer)
        outer.pack_start(self.build_header(), False, False, 0)
        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.content.set_border_width(10)
        outer.pack_start(self.content, True, True, 0)
        self.notebook = Gtk.Notebook()
        self.notebook.set_scrollable(True)
        self.notebook.get_style_context().add_class("main-tabs")
        rules_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        rules_page.set_border_width(2)
        rules_page.pack_start(self.build_overview(), False, False, 0)
        rules_page.pack_start(self.build_add_card(), False, False, 0)
        rules_page.pack_start(self.build_adult_card(), False, False, 0)
        rules_page.pack_start(self.build_list_card(), True, True, 0)
        self.notebook.append_page(rules_page, Gtk.Label(label=T("rules_tab")))
        self.notebook.append_page(self.build_squid_page(), Gtk.Label(label=T("squid_tab")))
        self.content.pack_start(self.notebook, True, True, 0)
        self.content.pack_start(self.build_footer(), False, False, 0)
        self.show_all()
        self.load_status(status)
        self.language_ready = True
        self.target_entry.grab_focus()

    def make_card(self, spacing: int = 7) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
        box.set_border_width(7)
        box.get_style_context().add_class("card")
        return box

    # ------------------------------------------------------------------ layout

    def build_header(self) -> Gtk.Widget:
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.set_border_width(8)
        header.get_style_context().add_class("topbar")
        image = (
            Gtk.Image.new_from_file(ICON)
            if Path(ICON).exists()
            else Gtk.Image.new_from_icon_name("security-high-symbolic", Gtk.IconSize.DIALOG)
        )
        image.set_pixel_size(30)
        header.pack_start(image, False, False, 0)
        titles = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        name = Gtk.Label(xalign=0)
        name.set_markup("<span size='large' weight='bold'>Eduka-Block</span>")
        name.get_style_context().add_class("brand-box")
        subtitle = Gtk.Label(label=T("app_subtitle"), xalign=0)
        subtitle.set_max_width_chars(28)
        subtitle.set_ellipsize(Pango.EllipsizeMode.END)
        subtitle.get_style_context().add_class("subtitle-box")
        titles.pack_start(name, False, False, 0)
        titles.pack_start(subtitle, False, False, 0)
        header.pack_start(titles, True, True, 0)
        self.busy = Gtk.Spinner()
        header.pack_start(self.busy, False, False, 0)
        language = Gtk.ComboBoxText()
        for code, label in LANGUAGES.items():
            language.append(code, label)
        language.set_active_id(CURRENT_LANGUAGE)
        language.set_tooltip_text(T("language"))
        language.connect("changed", self.on_language_change)
        header.pack_start(language, False, False, 0)
        lock = icon_button("changes-prevent-symbolic", "lock", self.on_lock)
        header.pack_start(lock, False, False, 0)
        menu = Gtk.MenuButton()
        menu.set_image(Gtk.Image.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.BUTTON))
        popover = Gtk.Popover.new(menu)
        menu_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        menu_box.set_border_width(8)
        for label_key, callback in (
            ("import_rules", self.on_import),
            ("export_rules", self.on_export),
            ("sync_now", self.on_sync_now),
            ("change_account", self.on_change_account),
            ("about", self.on_about),
        ):
            item = Gtk.ModelButton(label=T(label_key))
            item.connect("clicked", callback)
            menu_box.pack_start(item, False, False, 0)
        popover.add(menu_box)
        # Only realise the children: calling show_all() on the popover itself
        # would pop the menu open as soon as the window appears.
        menu_box.show_all()
        menu.set_popover(popover)
        header.pack_start(menu, False, False, 0)
        # Header controls stay out of reach while a privileged action runs.
        self.header_controls = (language, lock, menu)
        return header

    def build_overview(self) -> Gtk.Widget:
        card = self.make_card(5)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.overview_title = Gtk.Label(xalign=0)
        self.overview_title.set_ellipsize(Pango.EllipsizeMode.END)
        self.overview_title.get_style_context().add_class("section-title")
        row.pack_start(self.overview_title, True, True, 0)
        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.manual_badge = Gtk.Label()
        self.total_badge = Gtk.Label()
        self.ip_badge = Gtk.Label()
        for badge in (self.manual_badge, self.total_badge, self.ip_badge):
            badge.get_style_context().add_class("badge")
            stats.pack_start(badge, False, False, 0)
        row.pack_end(stats, False, False, 0)
        card.pack_start(row, False, False, 0)
        status_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.dns_status = Gtk.Label(xalign=0)
        self.dns_status.set_ellipsize(Pango.EllipsizeMode.END)
        self.dns_status.set_tooltip_text(T("browser_note"))
        status_row.pack_start(self.dns_status, True, True, 0)
        self.sync_label = Gtk.Label(xalign=1)
        self.sync_label.get_style_context().add_class("text-box")
        self.sync_label.set_tooltip_text(T("smart_tracking_tip"))
        status_row.pack_start(self.sync_label, False, False, 0)
        sync = icon_button("view-refresh-symbolic", "sync_now", self.on_sync_now)
        status_row.pack_start(sync, False, False, 0)
        card.pack_start(status_row, False, False, 0)
        return card

    def build_add_card(self) -> Gtk.Widget:
        card = self.make_card()
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.pack_start(section_title("add_title"), True, True, 0)
        self.smart_switch = Gtk.Switch(active=True)
        self.smart_switch.set_valign(Gtk.Align.CENTER)
        self.smart_switch.set_tooltip_text(T("smart_tracking_tip"))
        smart_label = Gtk.Label(label=T("smart_tracking"), xalign=0)
        smart_label.get_style_context().add_class("field-label")
        smart_label.set_tooltip_text(T("smart_tracking_tip"))
        header.pack_end(smart_label, False, False, 0)
        header.pack_end(self.smart_switch, False, False, 0)
        card.pack_start(header, False, False, 0)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
        self.target_entry = Gtk.Entry()
        self.target_entry.set_placeholder_text(T("target_hint"))
        self.target_entry.connect("activate", self.on_add)
        self.target_entry.connect("changed", self.on_target_changed)
        row.pack_start(self.target_entry, True, True, 0)
        self.category = Gtk.ComboBoxText()
        for key in CATEGORIES:
            self.category.append(key, T(CATEGORY_KEYS[key]))
        self.category.set_active_id("Manual")
        row.pack_start(self.category, False, False, 0)
        self.add_button = Gtk.Button(label=T("block_now"))
        self.add_button.get_style_context().add_class("suggested-action")
        self.add_button.set_sensitive(False)
        self.add_button.connect("clicked", self.on_add)
        row.pack_start(self.add_button, False, False, 0)
        card.pack_start(row, False, False, 0)
        return card

    def build_adult_card(self) -> Gtk.Widget:
        card = self.make_card(7)
        card.get_style_context().add_class("protection-card")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        icon = Gtk.Image.new_from_icon_name("security-high-symbolic", Gtk.IconSize.LARGE_TOOLBAR)
        row.pack_start(icon, False, False, 0)
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.adult_detail = Gtk.Label(xalign=0)
        self.adult_detail.set_line_wrap(True)
        self.adult_detail.get_style_context().add_class("text-box")
        self.adult_detail.set_tooltip_text(T("adult_source"))
        text_box.pack_start(section_title("adult_title"), False, False, 0)
        text_box.pack_start(self.adult_detail, False, False, 0)
        row.pack_start(text_box, True, True, 0)
        self.update_adult = Gtk.Button(label=T("update_list"))
        self.update_adult.set_valign(Gtk.Align.CENTER)
        self.update_adult.connect("clicked", self.on_update_adult)
        row.pack_start(self.update_adult, False, False, 0)
        self.adult_switch = Gtk.Switch()
        self.adult_switch.set_valign(Gtk.Align.CENTER)
        self.adult_switch.connect("state-set", self.on_adult_toggle)
        row.pack_start(self.adult_switch, False, False, 0)
        card.pack_start(row, False, False, 0)
        return card

    def build_list_card(self) -> Gtk.Widget:
        card = self.make_card()
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar.pack_start(section_title("list_title"), True, True, 0)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text(T("search_hint"))
        self.search.set_tooltip_text(T("search_shortcut"))
        self.search.connect("search-changed", self.on_search_changed)
        toolbar.pack_start(self.search, False, False, 0)
        toolbar.pack_start(icon_button("document-open-symbolic", "import_rules", self.on_import), False, False, 0)
        toolbar.pack_start(icon_button("document-save-as-symbolic", "export_rules", self.on_export), False, False, 0)
        card.pack_start(toolbar, False, False, 0)

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
        blocked_renderer = Gtk.CellRendererText(weight=Pango.Weight.BOLD, foreground="#d92f45")
        blocked_column = Gtk.TreeViewColumn(T("column_status"), blocked_renderer, text=COL_STATUS)
        blocked_column.set_resizable(True)
        self.tree.append_column(blocked_column)
        for title_key, column, expand in [
            ("column_target", COL_TARGET, True),
            ("column_type", COL_TYPE, False),
            ("column_category", COL_CATEGORY, False),
            ("column_coverage", COL_COVERAGE, True),
            ("column_added", COL_ADDED, False),
        ]:
            renderer = Gtk.CellRendererText()
            if expand:
                renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
            tree_column = Gtk.TreeViewColumn(T(title_key), renderer, text=column)
            tree_column.set_expand(expand)
            tree_column.set_resizable(True)
            tree_column.set_sort_column_id(column)
            self.tree.append_column(tree_column)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(90)
        scroll.add(self.tree)
        card.pack_start(scroll, True, True, 0)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.list_summary = Gtk.Label(xalign=0)
        self.list_summary.set_ellipsize(Pango.EllipsizeMode.END)
        self.list_summary.get_style_context().add_class("text-box")
        actions.pack_start(self.list_summary, True, True, 0)
        self.remove_button = Gtk.Button(label=T("remove_selected"))
        self.remove_button.get_style_context().add_class("destructive-action")
        self.remove_button.set_sensitive(False)
        self.remove_button.connect("clicked", self.on_remove)
        actions.pack_end(self.remove_button, False, False, 0)
        card.pack_start(actions, False, False, 0)
        return card

    def build_squid_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        page.set_border_width(2)

        status_card = self.make_card(6)
        status_card.get_style_context().add_class("protection-card")
        status_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
        icon = Gtk.Image.new_from_icon_name("network-server-symbolic", Gtk.IconSize.LARGE_TOOLBAR)
        status_row.pack_start(icon, False, False, 0)
        heading_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        self.squid_status = Gtk.Label(xalign=0)
        heading_box.pack_start(section_title("squid_title"), False, False, 0)
        heading_box.pack_start(self.squid_status, False, False, 0)
        status_row.pack_start(heading_box, True, True, 0)
        self.squid_switch = Gtk.Switch()
        self.squid_switch.set_valign(Gtk.Align.CENTER)
        self.squid_switch.connect("state-set", self.on_squid_toggle)
        status_row.pack_end(self.squid_switch, False, False, 0)
        status_card.pack_start(status_row, False, False, 0)
        description = Gtk.Label(label=T("squid_description"), xalign=0)
        description.set_line_wrap(True)
        description.get_style_context().add_class("info-box")
        status_card.pack_start(description, False, False, 0)
        page.pack_start(status_card, False, False, 0)

        commands_card = self.make_card(5)
        commands_card.pack_start(section_title("squid_commands_title"), False, False, 0)
        commands = Gtk.Label(label=T("squid_commands"), xalign=0)
        commands.set_selectable(True)
        commands.get_style_context().add_class("code-box")
        commands_card.pack_start(commands, False, False, 0)
        page.pack_start(commands_card, False, False, 0)

        keyword_card = self.make_card(6)
        keyword_card.pack_start(section_title("squid_keywords_title"), False, False, 0)
        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.squid_keyword_entry = Gtk.Entry()
        self.squid_keyword_entry.set_placeholder_text(T("squid_keyword_hint"))
        self.squid_keyword_entry.connect("activate", self.on_squid_add_keyword)
        add_row.pack_start(self.squid_keyword_entry, True, True, 0)
        add_keyword = Gtk.Button(label=T("squid_add_keyword"))
        add_keyword.get_style_context().add_class("suggested-action")
        add_keyword.connect("clicked", self.on_squid_add_keyword)
        add_row.pack_start(add_keyword, False, False, 0)
        keyword_card.pack_start(add_row, False, False, 0)

        self.squid_model = Gtk.ListStore(str)
        self.squid_tree = Gtk.TreeView(model=self.squid_model)
        self.squid_tree.set_headers_visible(False)
        self.squid_tree.connect("key-press-event", self.on_squid_tree_key)
        keyword_renderer = Gtk.CellRendererText()
        self.squid_tree.append_column(Gtk.TreeViewColumn(T("squid_keyword_column"), keyword_renderer, text=0))
        keyword_scroll = Gtk.ScrolledWindow()
        keyword_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        keyword_scroll.set_min_content_height(80)
        keyword_scroll.add(self.squid_tree)
        keyword_card.pack_start(keyword_scroll, True, True, 0)
        remove_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.squid_count = Gtk.Label(xalign=0)
        self.squid_count.get_style_context().add_class("text-box")
        remove_row.pack_start(self.squid_count, True, True, 0)
        remove_keyword = Gtk.Button(label=T("squid_remove_keyword"))
        remove_keyword.get_style_context().add_class("destructive-action")
        remove_keyword.connect("clicked", self.on_squid_remove_keyword)
        remove_row.pack_end(remove_keyword, False, False, 0)
        keyword_card.pack_start(remove_row, False, False, 0)
        page.pack_start(keyword_card, True, True, 0)
        return page

    def build_footer(self) -> Gtk.Widget:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        note = Gtk.Label(label=T("persistent_note"), xalign=0)
        note.set_ellipsize(Pango.EllipsizeMode.END)
        note.set_tooltip_text(T("persistent_note"))
        note.get_style_context().add_class("info-box")
        row.pack_start(note, True, True, 0)
        self.operation_label = Gtk.Label(label=T("ready"))
        self.operation_label.set_max_width_chars(40)
        self.operation_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        set_state_class(self.operation_label, "ok")
        row.pack_end(self.operation_label, False, False, 0)
        return row

    # ------------------------------------------------------------------ state

    def filter_visible(self, model, tree_iter, _data=None) -> bool:
        query = self.search.get_text().strip().lower() if hasattr(self, "search") else ""
        return not query or any(
            query in str(model[tree_iter][column]).lower()
            for column in (COL_TARGET, COL_TYPE, COL_CATEGORY, COL_COVERAGE)
        )

    def load_status(self, status: dict) -> None:
        self.status = status
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
        manual = int(status.get("manual_count", 0))
        tracked = int(status.get("tracked_ip_count", 0))
        self.manual_badge.set_text(T("manual_badge", count=f"{manual:,}"))
        self.total_badge.set_text(T("total_badge", count=f"{int(status.get('total_count', manual)):,}"))
        self.ip_badge.set_text(T("ip_badge", count=f"{tracked:,}"))

        adult = status.get("adult_protection", {})
        enabled = bool(adult.get("enabled"))
        protecting = manual > 0 or enabled
        self.overview_title.set_markup(
            "<b>"
            + GLib.markup_escape_text(T("overview_title" if protecting else "overview_title_idle"))
            + "</b>"
        )
        dns_engine = bool(status.get("dns_engine"))
        self.dns_status.set_text(T("dns_active" if dns_engine else "dns_fallback"))
        set_state_class(self.dns_status, "ok" if dns_engine else "warning")
        last_sync = local_time(status.get("smart_sync", {}).get("last_run"))
        self.sync_label.set_text(T("sync_last", date=last_sync) if last_sync else T("sync_never"))
        self.update_list_summary()

        updated = adult.get("updated_at")
        suffix = T("updated_suffix", date=str(updated)[:10]) if updated else ""
        self.adult_detail.set_text(
            T("adult_on", count=f"{int(adult.get('domain_count', 0)):,}", updated=suffix)
            if enabled
            else T("adult_off")
        )
        adult_context = self.adult_detail.get_style_context()
        adult_context.remove_class("blocked-summary")
        if enabled:
            adult_context.add_class("blocked-summary")

        squid = status.get("squid_proxy", {})
        self.squid_model.clear()
        keywords = squid.get("keywords", [])
        for keyword in keywords:
            self.squid_model.append([str(keyword)])
        self.squid_count.set_text(T("squid_keyword_count", count=len(keywords)))
        squid_enabled = bool(squid.get("enabled"))
        squid_running = bool(squid.get("running"))
        squid_installed = bool(squid.get("installed"))
        if squid_enabled and squid_running:
            squid_text, squid_state = "squid_status_on", "ok"
        elif squid_enabled:
            squid_text, squid_state = "squid_status_stopped", "warning"
        elif squid_installed:
            squid_text, squid_state = "squid_status_off", "ok"
        else:
            squid_text, squid_state = "squid_status_missing", "error"
        self.squid_status.set_text(T(squid_text))
        set_state_class(self.squid_status, squid_state)

        self.refreshing = True
        self.adult_switch.set_active(enabled)
        self.squid_switch.set_active(squid_enabled)
        self.squid_switch.set_sensitive(squid_installed or squid_enabled)
        self.refreshing = False
        self.update_adult.set_sensitive(enabled)
        self.on_selection_changed()

    def on_search_changed(self, *_args) -> None:
        self.filter.refilter()
        self.update_list_summary()

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

    def set_busy(self, active: bool, text: str, state: str = "ok") -> None:
        self.busy_active = active
        self.content.set_sensitive(not active)
        for control in self.header_controls:
            control.set_sensitive(not active)
        self.busy.start() if active else self.busy.stop()
        self.operation_label.set_text(text)
        set_state_class(self.operation_label, "warning" if active else state)
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
            if error:
                self.set_busy(False, T("operation_failed"), "error")
                message(self, T(failure_title_key), error, error=True)
                try:
                    self.load_status(helper_call("status"))
                except AppError:
                    pass
            else:
                self.load_status(result)
                self.set_busy(False, T(done_key))
                if on_success:
                    on_success(result)
            return False

        def worker() -> None:
            try:
                GLib.idle_add(done, helper_call(action, payload, privileged=True), None)
            except AppError as exc:
                GLib.idle_add(done, None, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ rules

    def on_target_changed(self, *_args) -> None:
        self.add_button.set_sensitive(bool(self.target_entry.get_text().strip()))

    def on_add(self, *_args) -> None:
        raw = self.target_entry.get_text()
        if not raw.strip():
            return
        try:
            normalized, kind = normalize_target(raw)
        except ValidationError as exc:
            message(self, T("invalid_target_title"), T(exc.code), error=True)
            return
        if not confirm(
            self,
            T("confirm_add_title"),
            T("confirm_add_body", target=normalized, kind=T(TYPE_KEYS.get(kind, kind))),
        ):
            return
        self.run_helper(
            "add",
            {
                "target": raw,
                "category": self.category.get_active_id() or "Manual",
                "smart": self.smart_switch.get_active(),
            },
            "applying",
            "applied",
            "add_failed_title",
            on_success=lambda _result: self.target_entry.set_text(""),
        )

    def selected_rules(self) -> list[tuple[str, str]]:
        model, paths = self.tree.get_selection().get_selected_rows()
        return [(model[path][COL_ID], model[path][COL_TARGET]) for path in paths]

    def on_selection_changed(self, *_args) -> None:
        self.remove_button.set_sensitive(bool(self.selected_rules()))

    def on_remove(self, *_args) -> None:
        selected = self.selected_rules()
        if not selected:
            message(self, T("select_rule_title"), T("select_rule_body"))
            return
        if len(selected) == 1:
            body = T("confirm_remove_body", target=selected[0][1])
        else:
            body = T("confirm_remove_many_body", count=len(selected))
        if not confirm(self, T("confirm_remove_title"), body):
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
        if not confirm(self, T("import_confirm_title", count=len(items)), T("import_confirm_body")):
            return

        def summary(result: dict) -> None:
            counts = result.get("import_result", {})
            message(
                self,
                T("import_done_title"),
                T(
                    "import_done_body",
                    added=counts.get("added", 0),
                    skipped=counts.get("skipped", 0),
                    invalid=counts.get("invalid", 0),
                ),
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
            message(self, T("export_failed_title"), T("no_rules"))
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
        self.operation_label.set_text(T("export_done_body", count=len(entries), path=path))
        set_state_class(self.operation_label, "ok")

    def on_sync_now(self, *_args) -> None:
        self.run_helper("sync-smart-ips", None, "syncing", "synced", "sync_failed_title")

    # ------------------------------------------------------------------ adult

    def on_adult_toggle(self, _switch, requested: bool) -> bool:
        if self.refreshing:
            return False
        current = bool(self.status.get("adult_protection", {}).get("enabled"))
        if requested == current:
            return False
        accepted = confirm(
            self,
            T("adult_enable_title" if requested else "adult_disable_title"),
            T("adult_enable_body" if requested else "adult_disable_body"),
        )
        if not accepted:
            self.refreshing = True
            self.adult_switch.set_active(current)
            self.refreshing = False
            return True
        self.run_adult_action("adult-enable" if requested else "adult-disable")
        return True

    def on_update_adult(self, *_args) -> None:
        if confirm(self, T("adult_update_title"), T("adult_update_body")):
            self.run_adult_action("adult-update")

    def run_adult_action(self, action: str) -> None:
        self.run_helper(
            action,
            None,
            "releasing" if action == "adult-disable" else "downloading",
            "updated",
            "adult_failed_title",
        )

    # ------------------------------------------------------------------ squid

    def current_squid_keywords(self) -> list[str]:
        return [str(row[0]) for row in self.squid_model]

    def on_squid_toggle(self, _switch, requested: bool) -> bool:
        if self.refreshing:
            return False
        current = bool(self.status.get("squid_proxy", {}).get("enabled"))
        if requested == current:
            return False
        accepted = confirm(
            self,
            T("squid_enable_title" if requested else "squid_disable_title"),
            T("squid_enable_body" if requested else "squid_disable_body"),
        )
        if not accepted:
            self.refreshing = True
            self.squid_switch.set_active(current)
            self.refreshing = False
            return True
        self.run_squid_update(requested, self.current_squid_keywords())
        return True

    def on_squid_add_keyword(self, *_args) -> None:
        keyword = " ".join(self.squid_keyword_entry.get_text().strip().lower().split())
        if not keyword:
            message(self, T("squid_invalid_title"), T("err_squid_keyword"), error=True)
            return
        keywords = self.current_squid_keywords()
        if keyword in keywords:
            message(self, T("squid_invalid_title"), T("squid_keyword_exists", keyword=keyword))
            return
        keywords.append(keyword)
        enabled = bool(self.status.get("squid_proxy", {}).get("enabled"))
        self.run_squid_update(enabled, keywords, clear_entry=True)

    def on_squid_remove_keyword(self, *_args) -> None:
        model, tree_iter = self.squid_tree.get_selection().get_selected()
        if tree_iter is None:
            message(self, T("squid_select_title"), T("squid_select_body"))
            return
        selected = str(model[tree_iter][0])
        keywords = [keyword for keyword in self.current_squid_keywords() if keyword != selected]
        if not keywords:
            message(self, T("squid_invalid_title"), T("err_squid_keywords_limit"), error=True)
            return
        enabled = bool(self.status.get("squid_proxy", {}).get("enabled"))
        self.run_squid_update(enabled, keywords)

    def on_squid_tree_key(self, _widget, event) -> bool:
        if event.keyval == Gdk.KEY_Delete:
            self.on_squid_remove_keyword()
            return True
        return False

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
            message(self, T("account_changed_title"), T("account_changed_body"))

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
            self.notebook.set_current_page(0)
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
