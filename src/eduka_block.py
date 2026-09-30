#!/usr/bin/python3
"""Eduka-Block 0.4.1 GTK interface."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402


LIB_DIR = Path("/usr/lib/eduka-block")
if LIB_DIR.is_dir():
    sys.path.insert(0, str(LIB_DIR))
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from eduka_block_common import (  # noqa: E402
    APP_VERSION,
    CREDENTIALS_PATH,
    ValidationError,
    normalize_target,
    verify_credentials,
)
from eduka_block_i18n import LANGUAGES, load_language, save_language, tr  # noqa: E402


HELPER = "/usr/lib/eduka-block/eduka-block-helper"
ICON = "/usr/share/icons/hicolor/scalable/apps/eduka-block.svg"
CSS = "/usr/share/eduka-block/eduka-block.css"
CONFIG_PATH = Path.home() / ".config" / "eduka-block" / "settings.json"
AUTO_LOCK_SECONDS = 600
RESPONSE_CHANGE_ACCOUNT = 1001
CURRENT_LANGUAGE = load_language(CONFIG_PATH)


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
            timeout=180 if action.startswith("adult-") else 120 if action.startswith("squid-") else 60,
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


def load_css() -> None:
    provider = Gtk.CssProvider()
    css_path = Path(CSS)
    if not css_path.exists():
        css_path = Path(__file__).resolve().parent.parent / "assets" / "eduka-block.css"
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
    result = dialog.run() == Gtk.ResponseType.OK
    dialog.destroy()
    return result


class AccountDialog(Gtk.Dialog):
    def __init__(self, setup: bool, parent: Gtk.Window | None = None):
        super().__init__(transient_for=parent, modal=True)
        self.setup = setup
        self.set_default_size(430, 370 if setup else 300)
        self.set_resizable(False)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.get_style_context().add_class("auth-dialog")
        self.cancel_button = self.add_button("", Gtk.ResponseType.CANCEL)
        self.change_button = None
        if not setup:
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
        self.heading.set_xalign(0)
        self.heading.get_style_context().add_class("boxed-heading")
        box.pack_start(self.heading, False, False, 0)
        self.note = Gtk.Label()
        self.note.set_line_wrap(True)
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
        self.password = Gtk.Entry()
        self.password.set_visibility(False)
        self.password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.password.set_activates_default(True)
        grid.attach(self.password, 1, 2, 1, 1)
        self.confirm_label = None
        self.confirm_password = None
        self.password_status = None
        if setup:
            self.confirm_label = Gtk.Label(xalign=0)
            self.confirm_label.get_style_context().add_class("field-label")
            grid.attach(self.confirm_label, 0, 3, 1, 1)
            self.confirm_password = Gtk.Entry()
            self.confirm_password.set_visibility(False)
            self.confirm_password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
            self.confirm_password.set_activates_default(True)
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

    def update_text(self) -> None:
        self.set_title(T("setup_title" if self.setup else "login_title"))
        self.cancel_button.set_label(T("cancel"))
        self.action_button.set_label(T("create_account" if self.setup else "sign_in"))
        if self.change_button:
            self.change_button.set_label(T("change_account"))
        self.heading.set_markup(
            "<span size='large' weight='bold'>"
            + GLib.markup_escape_text(T("protect_settings" if self.setup else "manager_authorization"))
            + "</span>"
        )
        self.note.set_text(T("setup_note" if self.setup else "login_note"))
        self.language_label.set_text(T("language"))
        self.username_label.set_text(T("username"))
        self.username.set_placeholder_text(T("username_hint"))
        self.password_label.set_text(T("password"))
        self.password.set_placeholder_text(T("password_minimum"))
        if self.confirm_label:
            self.confirm_label.set_text(T("repeat_password"))
            self.confirm_password.set_placeholder_text(T("repeat_password"))
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
        context = self.password_status.get_style_context()
        for style_class in ("status-ok", "status-warning", "status-error"):
            context.remove_class(style_class)

        if len(password) < 5:
            self.password_status.set_text(T("password_minimum"))
            context.add_class("status-warning")
        elif not confirmation:
            self.password_status.set_text(T("password_confirm_prompt"))
            context.add_class("status-warning")
        elif password != confirmation:
            self.password_status.set_text(T("password_mismatch_inline"))
            context.add_class("status-error")
        else:
            self.password_status.set_text(T("password_ready"))
            context.add_class("status-ok")

        username_valid = 3 <= len(self.username.get_text().strip()) <= 64
        self.action_button.set_sensitive(
            username_valid and len(password) >= 5 and password == confirmation
        )


class MainWindow(Gtk.Window):
    def __init__(self, status: dict):
        super().__init__(title=f"Eduka-Block {APP_VERSION}")
        self.status = status
        self.lock_requested = False
        self.restart_requested = False
        self.refreshing = False
        self.language_ready = False
        self.last_activity = time.monotonic()
        self.set_default_size(900, 600)
        self.set_size_request(700, 500)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.get_style_context().add_class("eduka-window")
        if Path(ICON).exists():
            self.set_icon_from_file(ICON)
        self.connect("destroy", lambda *_: Gtk.main_quit())
        self.connect("event", self.on_activity)
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
        self.load_status(status)
        self.language_ready = True
        self.show_all()

    def make_card(self, spacing: int = 7) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
        box.set_border_width(7)
        box.get_style_context().add_class("card")
        return box

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
        lock = Gtk.Button.new_from_icon_name("changes-prevent-symbolic", Gtk.IconSize.BUTTON)
        lock.set_tooltip_text(T("lock"))
        lock.connect("clicked", self.on_lock)
        header.pack_start(lock, False, False, 0)
        menu = Gtk.MenuButton()
        menu.set_image(Gtk.Image.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.BUTTON))
        popover = Gtk.Popover.new(menu)
        menu_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        menu_box.set_border_width(8)
        change = Gtk.ModelButton(label=T("change_account"))
        change.connect("clicked", self.on_change_account)
        about = Gtk.ModelButton(label=T("about"))
        about.connect("clicked", self.on_about)
        menu_box.pack_start(change, False, False, 0)
        menu_box.pack_start(about, False, False, 0)
        popover.add(menu_box)
        popover.show_all()
        menu.set_popover(popover)
        header.pack_start(menu, False, False, 0)
        return header

    def build_overview(self) -> Gtk.Widget:
        card = self.make_card(5)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title = Gtk.Label(xalign=0)
        title.set_ellipsize(Pango.EllipsizeMode.END)
        title.set_markup(f"<b>{GLib.markup_escape_text(T('overview_title'))}</b>")
        title.get_style_context().add_class("section-title")
        row.pack_start(title, True, True, 0)
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
        desc = Gtk.Label(label=T("overview_text"), xalign=0)
        desc.get_style_context().add_class("text-box")
        desc.set_tooltip_text(T("browser_note"))
        self.dns_status = Gtk.Label(xalign=0)
        self.dns_status.get_style_context().add_class("status-ok")
        status_row.pack_start(desc, True, True, 0)
        status_row.pack_end(self.dns_status, False, False, 0)
        card.pack_start(status_row, False, False, 0)
        return card

    def build_add_card(self) -> Gtk.Widget:
        card = self.make_card()
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title = Gtk.Label(xalign=0)
        title.set_ellipsize(Pango.EllipsizeMode.END)
        title.set_markup(f"<b>{GLib.markup_escape_text(T('add_title'))}</b>")
        title.get_style_context().add_class("section-title")
        header.pack_start(title, True, True, 0)
        self.smart_switch = Gtk.Switch(active=True)
        self.smart_switch.set_valign(Gtk.Align.CENTER)
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
        row.pack_start(self.target_entry, True, True, 0)
        self.category = Gtk.ComboBoxText()
        for key, text_key in CATEGORY_KEYS.items():
            self.category.append(key, T(text_key))
        self.category.set_active_id("Manual")
        row.pack_start(self.category, False, False, 0)
        add = Gtk.Button(label=T("block_now"))
        add.get_style_context().add_class("suggested-action")
        add.connect("clicked", self.on_add)
        row.pack_start(add, False, False, 0)
        card.pack_start(row, False, False, 0)
        return card

    def build_adult_card(self) -> Gtk.Widget:
        card = self.make_card(7)
        card.get_style_context().add_class("protection-card")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        icon = Gtk.Image.new_from_icon_name("security-high-symbolic", Gtk.IconSize.LARGE_TOOLBAR)
        row.pack_start(icon, False, False, 0)
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        heading = Gtk.Label(xalign=0)
        heading.set_markup(f"<b>{GLib.markup_escape_text(T('adult_title'))}</b>")
        heading.get_style_context().add_class("section-title")
        self.adult_detail = Gtk.Label(xalign=0)
        self.adult_detail.set_line_wrap(True)
        self.adult_detail.get_style_context().add_class("text-box")
        text_box.pack_start(heading, False, False, 0)
        text_box.pack_start(self.adult_detail, False, False, 0)
        row.pack_start(text_box, True, True, 0)
        self.update_adult = Gtk.Button(label=T("update_list"))
        self.update_adult.connect("clicked", self.on_update_adult)
        row.pack_start(self.update_adult, False, False, 0)
        self.adult_switch = Gtk.Switch()
        self.adult_switch.set_valign(Gtk.Align.CENTER)
        self.adult_switch.connect("state-set", self.on_adult_toggle)
        row.pack_start(self.adult_switch, False, False, 0)
        card.pack_start(row, False, False, 0)
        self.adult_detail.set_tooltip_text(T("adult_source"))
        return card

    def build_list_card(self) -> Gtk.Widget:
        card = self.make_card()
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
        heading = Gtk.Label(xalign=0)
        heading.set_markup(f"<b>{GLib.markup_escape_text(T('list_title'))}</b>")
        heading.get_style_context().add_class("section-title")
        toolbar.pack_start(heading, True, True, 0)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text(T("search_hint"))
        self.search.connect("search-changed", lambda *_: self.filter.refilter())
        toolbar.pack_end(self.search, False, False, 0)
        card.pack_start(toolbar, False, False, 0)
        self.model = Gtk.ListStore(str, str, str, str, str, str, str)
        self.filter = self.model.filter_new()
        self.filter.set_visible_func(self.filter_visible)
        self.tree = Gtk.TreeView(model=self.filter)
        self.tree.set_enable_search(False)
        self.tree.connect("key-press-event", self.on_tree_key)
        blocked_renderer = Gtk.CellRendererText(
            weight=Pango.Weight.BOLD,
            foreground="#d92f45",
        )
        blocked_column = Gtk.TreeViewColumn(T("column_status"), blocked_renderer, text=1)
        blocked_column.set_resizable(True)
        self.tree.append_column(blocked_column)
        for title_key, column, expand in [
            ("column_target", 2, True),
            ("column_type", 3, False),
            ("column_category", 4, False),
            ("column_coverage", 5, True),
            ("column_added", 6, False),
        ]:
            renderer = Gtk.CellRendererText()
            tree_column = Gtk.TreeViewColumn(T(title_key), renderer, text=column)
            tree_column.set_expand(expand)
            tree_column.set_resizable(True)
            self.tree.append_column(tree_column)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(90)
        scroll.add(self.tree)
        card.pack_start(scroll, True, True, 0)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.empty_label = Gtk.Label(label=T("no_rules"), xalign=0)
        self.empty_label.get_style_context().add_class("text-box")
        actions.pack_start(self.empty_label, True, True, 0)
        remove = Gtk.Button(label=T("remove_selected"))
        remove.get_style_context().add_class("destructive-action")
        remove.connect("clicked", self.on_remove)
        actions.pack_end(remove, False, False, 0)
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
        heading = Gtk.Label(xalign=0)
        heading.set_markup(f"<b>{GLib.markup_escape_text(T('squid_title'))}</b>")
        heading.get_style_context().add_class("section-title")
        self.squid_status = Gtk.Label(xalign=0)
        self.squid_status.get_style_context().add_class("status-ok")
        heading_box.pack_start(heading, False, False, 0)
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
        commands_title = Gtk.Label(label=T("squid_commands_title"), xalign=0)
        commands_title.get_style_context().add_class("section-title")
        commands = Gtk.Label(label=T("squid_commands"), xalign=0)
        commands.set_selectable(True)
        commands.get_style_context().add_class("code-box")
        commands_card.pack_start(commands_title, False, False, 0)
        commands_card.pack_start(commands, False, False, 0)
        page.pack_start(commands_card, False, False, 0)

        keyword_card = self.make_card(6)
        keywords_title = Gtk.Label(label=T("squid_keywords_title"), xalign=0)
        keywords_title.get_style_context().add_class("section-title")
        keyword_card.pack_start(keywords_title, False, False, 0)
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
        keyword_renderer = Gtk.CellRendererText()
        self.squid_tree.append_column(Gtk.TreeViewColumn(T("squid_keyword_column"), keyword_renderer, text=0))
        keyword_scroll = Gtk.ScrolledWindow()
        keyword_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        keyword_scroll.set_min_content_height(80)
        keyword_scroll.add(self.squid_tree)
        keyword_card.pack_start(keyword_scroll, True, True, 0)
        remove_keyword = Gtk.Button(label=T("squid_remove_keyword"))
        remove_keyword.get_style_context().add_class("destructive-action")
        remove_keyword.connect("clicked", self.on_squid_remove_keyword)
        keyword_card.pack_end(remove_keyword, False, False, 0)
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
        self.operation_label.get_style_context().add_class("status-ok")
        row.pack_end(self.operation_label, False, False, 0)
        return row

    def filter_visible(self, model, tree_iter, _data=None) -> bool:
        query = self.search.get_text().strip().lower() if hasattr(self, "search") else ""
        return not query or any(query in str(model[tree_iter][c]).lower() for c in (1, 2, 3, 4, 5))

    def load_status(self, status: dict) -> None:
        self.status = status
        self.model.clear()
        for entry in sorted(status.get("entries", []), key=lambda item: item.get("value", "")):
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
        self.dns_status.set_text(T("dns_active" if status.get("dns_engine") else "dns_fallback"))
        self.empty_label.set_visible(manual == 0)
        adult = status.get("adult_protection", {})
        enabled = bool(adult.get("enabled"))
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
        for keyword in squid.get("keywords", []):
            self.squid_model.append([str(keyword)])
        squid_enabled = bool(squid.get("enabled"))
        squid_running = bool(squid.get("running"))
        squid_installed = bool(squid.get("installed"))
        self.squid_status.set_text(
            T("squid_status_on")
            if squid_enabled and squid_running
            else T("squid_status_stopped")
            if squid_enabled
            else T("squid_status_off")
            if squid_installed
            else T("squid_status_missing")
        )
        self.refreshing = True
        self.adult_switch.set_active(enabled)
        self.squid_switch.set_active(squid_enabled)
        self.refreshing = False
        self.update_adult.set_sensitive(enabled)

    def set_busy(self, active: bool, text: str) -> None:
        self.content.set_sensitive(not active)
        self.busy.start() if active else self.busy.stop()
        self.operation_label.set_text(text)

    def on_add(self, *_args) -> None:
        raw = self.target_entry.get_text()
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
        self.set_busy(True, T("applying"))
        while Gtk.events_pending():
            Gtk.main_iteration()
        try:
            status = helper_call(
                "add",
                {
                    "target": raw,
                    "category": self.category.get_active_id() or "Manual",
                    "smart": self.smart_switch.get_active(),
                },
                privileged=True,
            )
            self.target_entry.set_text("")
            self.load_status(status)
            self.set_busy(False, T("applied"))
        except AppError as exc:
            self.set_busy(False, T("operation_failed"))
            message(self, T("add_failed_title"), str(exc), error=True)

    def selected_id(self) -> tuple[str, str] | None:
        model, tree_iter = self.tree.get_selection().get_selected()
        return (model[tree_iter][0], model[tree_iter][2]) if tree_iter else None

    def on_remove(self, *_args) -> None:
        selected = self.selected_id()
        if not selected:
            message(self, T("select_rule_title"), T("select_rule_body"))
            return
        entry_id, value = selected
        if not confirm(self, T("confirm_remove_title"), T("confirm_remove_body", target=value)):
            return
        self.set_busy(True, T("removing"))
        while Gtk.events_pending():
            Gtk.main_iteration()
        try:
            self.load_status(helper_call("remove", {"id": entry_id}, privileged=True))
            self.set_busy(False, T("removed"))
        except AppError as exc:
            self.set_busy(False, T("operation_failed"))
            message(self, T("remove_failed_title"), str(exc), error=True)

    def on_tree_key(self, _widget, event) -> bool:
        if event.keyval == Gdk.KEY_Delete:
            self.on_remove()
            return True
        return False

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
        self.set_busy(True, T("releasing" if action == "adult-disable" else "downloading"))

        def done(result, error) -> bool:
            if error:
                self.set_busy(False, T("operation_failed"))
                message(self, T("adult_failed_title"), error, error=True)
                try:
                    self.load_status(helper_call("status"))
                except AppError:
                    pass
            else:
                self.load_status(result)
                self.set_busy(False, T("updated"))
            return False

        def worker() -> None:
            try:
                GLib.idle_add(done, helper_call(action, privileged=True), None)
            except AppError as exc:
                GLib.idle_add(done, None, str(exc))

        threading.Thread(target=worker, daemon=True).start()

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
        keyword = self.squid_keyword_entry.get_text().strip()
        if not keyword:
            message(self, T("squid_invalid_title"), T("err_squid_keyword"), error=True)
            return
        keywords = self.current_squid_keywords()
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

    def run_squid_update(self, enabled: bool, keywords: list[str], clear_entry: bool = False) -> None:
        self.set_busy(True, T("squid_working"))

        def done(result, error) -> bool:
            if error:
                self.set_busy(False, T("operation_failed"))
                message(self, T("squid_failed_title"), error, error=True)
                try:
                    self.load_status(helper_call("status"))
                except AppError:
                    pass
            else:
                self.load_status(result)
                if clear_entry:
                    self.squid_keyword_entry.set_text("")
                self.set_busy(False, T("squid_applied"))
            return False

        def worker() -> None:
            try:
                result = helper_call(
                    "squid-configure",
                    {"enabled": enabled, "keywords": keywords},
                    privileged=True,
                )
                GLib.idle_add(done, result, None)
            except AppError as exc:
                GLib.idle_add(done, None, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def on_change_account(self, *_args) -> None:
        dialog = AccountDialog(setup=True, parent=self)
        dialog.set_title(T("change_account_title"))
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
                dialog.destroy()
                message(self, T("account_changed_title"), T("account_changed_body"))
                return
            except AppError as exc:
                message(dialog, T("account_change_failed"), str(exc), error=True)
        dialog.destroy()

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
        if not self.language_ready:
            return
        code = combo.get_active_id()
        if code and code != CURRENT_LANGUAGE:
            set_language(code)
            self.restart_requested = True
            self.destroy()

    def on_activity(self, *_args) -> bool:
        self.last_activity = time.monotonic()
        return False

    def auto_lock_check(self) -> bool:
        if not self.get_visible():
            return False
        if time.monotonic() - self.last_activity >= AUTO_LOCK_SECONDS:
            self.on_lock()
            return False
        return True

    def on_lock(self, *_args) -> None:
        self.lock_requested = True
        self.destroy()


def authenticate() -> dict | None:
    try:
        status = helper_call("status")
    except AppError as exc:
        message(None, T("startup_failed_title"), str(exc), error=True)
        return None
    if not status.get("configured"):
        dialog = AccountDialog(setup=True)
        while True:
            if dialog.run() != Gtk.ResponseType.OK:
                dialog.destroy()
                return None
            username, password = dialog.values()
            if not dialog.passwords_match():
                message(dialog, T("password_mismatch_title"), T("password_mismatch_body"), error=True)
                continue
            try:
                status = helper_call(
                    "setup", {"username": username, "password": password}, privileged=True
                )
                dialog.destroy()
                break
            except AppError as exc:
                message(dialog, T("account_create_failed"), str(exc), error=True)
        message(None, T("account_created_title"), T("account_created_body"))

    dialog = AccountDialog(setup=False)
    attempts = 0
    while True:
        response = dialog.run()
        if response == Gtk.ResponseType.CANCEL or response == Gtk.ResponseType.DELETE_EVENT:
            dialog.destroy()
            return None
        username, password = dialog.values()
        if response == RESPONSE_CHANGE_ACCOUNT:
            if not verify_credentials(username, password, CREDENTIALS_PATH):
                attempts += 1
                dialog.password.set_text("")
                message(dialog, T("login_failed_title"), T("login_failed_body"), error=True)
                if attempts >= 5:
                    dialog.destroy()
                    message(None, T("too_many_title"), T("too_many_body"), error=True)
                    return None
                continue
            dialog.hide()
            change_dialog = AccountDialog(setup=True)
            change_dialog.set_title(T("change_account_title"))
            changed_username = None
            while True:
                if change_dialog.run() != Gtk.ResponseType.OK:
                    break
                new_username, new_password = change_dialog.values()
                if not change_dialog.passwords_match():
                    message(
                        change_dialog,
                        T("password_mismatch_title"),
                        T("password_mismatch_body"),
                        error=True,
                    )
                    continue
                try:
                    helper_call(
                        "change-credentials",
                        {"username": new_username, "password": new_password},
                        privileged=True,
                    )
                    changed_username = new_username
                    break
                except AppError as exc:
                    message(change_dialog, T("account_change_failed"), str(exc), error=True)
            change_dialog.destroy()
            dialog.show_all()
            dialog.password.set_text("")
            if changed_username:
                dialog.username.set_text(changed_username)
                message(dialog, T("account_changed_title"), T("account_changed_body"))
            continue
        if response != Gtk.ResponseType.OK:
            continue
        if verify_credentials(username, password, CREDENTIALS_PATH):
            dialog.destroy()
            return helper_call("status")
        attempts += 1
        dialog.password.set_text("")
        message(dialog, T("login_failed_title"), T("login_failed_body"), error=True)
        if attempts >= 5:
            dialog.destroy()
            message(None, T("too_many_title"), T("too_many_body"), error=True)
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
