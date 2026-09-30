import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from eduka_block_common import (  # noqa: E402
    APP_VERSION,
    ValidationError,
    aliases_for_domain,
    create_credentials_text,
    export_rules_text,
    normalize_target,
    parse_rules_text,
    validate_account,
    verify_credentials,
)
from eduka_block_helper import (  # noqa: E402
    BEGIN_MARKER,
    END_MARKER,
    SQUID_BEGIN_MARKER,
    HelperError,
    default_state,
    firewall_elements,
    install_squid_include,
    load_state,
    migrate_state,
    normalize_squid_keywords,
    parse_hosts_download,
    parse_resolv_nameservers,
    remove_managed_section,
    remove_squid_include,
    render_dnsmasq,
    render_hosts,
    render_squid_config,
    render_squid_keywords,
    save_state,
)
import eduka_block_helper as helper  # noqa: E402
from eduka_block_i18n import EN, FALLBACKS, LANGUAGES, TRANSLATIONS, tr  # noqa: E402


class ValidationTests(unittest.TestCase):
    def test_normalizes_url_domain_and_ip(self):
        self.assertEqual(normalize_target("HTTPS://WWW.Example.org/path?q=1"), ("www.example.org", "domain"))
        self.assertEqual(normalize_target("example.org:443"), ("example.org", "domain"))
        self.assertEqual(normalize_target("203.0.113.10"), ("203.0.113.10", "ipv4"))
        self.assertEqual(normalize_target("2001:db8::25"), ("2001:db8::25", "ipv6"))
        self.assertEqual(normalize_target("203.0.113.7/24"), ("203.0.113.0/24", "ipv4_network"))
        self.assertEqual(normalize_target("2001:db8::1/48"), ("2001:db8::/48", "ipv6_network"))

    def test_rejects_dangerous_or_invalid_targets(self):
        for value in ("", "localhost", "*.example.org", "file:///etc/passwd", "127.0.0.1", "::1"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                normalize_target(value)

    def test_aliases_only_common_pair(self):
        self.assertEqual(aliases_for_domain("example.org"), ["example.org", "www.example.org"])
        self.assertEqual(aliases_for_domain("www.example.org"), ["example.org", "www.example.org"])
        self.assertEqual(aliases_for_domain("school.example.org"), ["school.example.org"])


class CredentialTests(unittest.TestCase):
    def test_password_minimum_is_five_characters(self):
        validate_account("Teacher", "12345")
        with self.assertRaises(ValidationError):
            validate_account("Teacher", "1234")

    def test_hash_roundtrip_and_no_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.txt"
            content = create_credentials_text("Teacher", "StrongPassword!")
            path.write_text(content, encoding="utf-8")
            self.assertNotIn("StrongPassword!", content)
            self.assertTrue(verify_credentials("Teacher", "StrongPassword!", path))
            self.assertFalse(verify_credentials("Teacher", "wrong-password", path))
            self.assertFalse(verify_credentials("Student", "StrongPassword!", path))

    def test_unicode_username_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.txt"
            path.write_text(create_credentials_text("Profesór", "abcde"), encoding="utf-8")
            self.assertTrue(verify_credentials("Profesór", "abcde", path))


class HostsTests(unittest.TestCase):
    def test_remove_managed_section_preserves_unrelated_content(self):
        content = (
            "127.0.0.1 localhost\n"
            f"{BEGIN_MARKER}\n0.0.0.0 example.org\n{END_MARKER}\n"
            "192.0.2.1 intranet.example\n"
        )
        self.assertEqual(
            remove_managed_section(content),
            "127.0.0.1 localhost\n192.0.2.1 intranet.example\n",
        )

    def test_render_hosts_adds_domain_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / "hosts"
            backup = root / "backup"
            adult = root / "adult.txt"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            state = default_state()
            state["entries"].append(
                {
                    "id": "one",
                    "value": "example.org",
                    "kind": "domain",
                    "category": "Manual",
                    "created_at": "2026-07-21T00:00:00+00:00",
                }
            )
            render_hosts(state, hosts, adult, backup)
            content = hosts.read_text(encoding="utf-8")
            self.assertIn("0.0.0.0 example.org", content)
            self.assertIn(":: www.example.org", content)
            self.assertEqual(backup.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")

    def test_parse_compressed_hosts_download(self):
        entries = " ".join(f"adult-{number}.example" for number in range(1200))
        parsed = parse_hosts_download("# source metadata\n0.0.0.0 " + entries + "\n")
        self.assertEqual(len(parsed), 1200)
        self.assertIn("adult-42.example", parsed)

    def test_dnsmasq_rules_cover_domain_and_subdomains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eduka-block.conf"
            state = default_state()
            state["entries"].append(
                {
                    "id": "one",
                    "value": "example.org",
                    "kind": "domain",
                    "category": "Manual",
                    "smart": True,
                    "resolved_ips": [],
                    "created_at": "2026-07-21T00:00:00+00:00",
                }
            )
            render_dnsmasq(state, path)
            content = path.read_text(encoding="utf-8")
            self.assertIn("local=/example.org/", content)
            self.assertIn("address=/example.org/0.0.0.0", content)
            self.assertIn("address=/example.org/::", content)

    def test_resolv_nameserver_parser_skips_local_stub(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resolv.conf"
            path.write_text("nameserver 127.0.0.53\nnameserver 9.9.9.9\n", encoding="utf-8")
            self.assertEqual(parse_resolv_nameservers([path]), ["9.9.9.9"])


class StateTests(unittest.TestCase):
    def test_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = default_state()
            save_state(state, path)
            self.assertEqual(load_state(path), state)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schema"], 3)

    def test_migrates_version_01_state(self):
        old = {
            "schema": 1,
            "entries": [
                {
                    "id": "old",
                    "value": "example.org",
                    "kind": "domain",
                    "category": "Manual",
                    "created_at": "2026-07-21T00:00:00+00:00",
                }
            ],
            "adult_protection": {"enabled": False, "domain_count": 0},
        }
        migrated = migrate_state(old)
        self.assertEqual(migrated["schema"], 3)
        self.assertTrue(migrated["entries"][0]["smart"])
        self.assertEqual(migrated["entries"][0]["resolved_ips"], [])
        self.assertFalse(migrated["squid_proxy"]["enabled"])
        self.assertIn("porn", migrated["squid_proxy"]["keywords"])

    def test_firewall_includes_ranges_and_smart_ips(self):
        state = default_state()
        state["entries"] = [
            {
                "value": "example.org",
                "kind": "domain",
                "smart": True,
                "resolved_ips": ["93.184.216.34", "2606:2800:220:1::34"],
            },
            {"value": "203.0.113.0/24", "kind": "ipv4_network", "smart": False},
        ]
        ipv4, ipv6 = firewall_elements(state)
        self.assertIn("93.184.216.34", ipv4)
        self.assertIn("203.0.113.0/24", ipv4)
        self.assertIn("2606:2800:220:1::34", ipv6)

    def test_firewall_is_checked_and_replaced_in_one_atomic_batch(self):
        state = default_state()
        state["entries"] = [
            {"value": "203.0.113.9", "kind": "ipv4", "smart": False},
        ]
        completed = lambda code=0: subprocess.CompletedProcess([], code, "", "")
        with patch.object(helper, "nft_binary", return_value="/usr/sbin/nft"), patch.object(
            helper.subprocess,
            "run",
            side_effect=[completed(), completed(), completed()],
        ) as run:
            helper.apply_firewall(state)
        checked = run.call_args_list[1]
        applied = run.call_args_list[2]
        self.assertIn("--check", checked.args[0])
        self.assertEqual(checked.kwargs["input"], applied.kwargs["input"])
        self.assertIn("delete table inet eduka_block", checked.kwargs["input"])
        self.assertIn("table inet eduka_block", checked.kwargs["input"])
        self.assertIn("203.0.113.9", checked.kwargs["input"])

    def test_new_domain_enables_smart_tracking(self):
        with patch.object(helper, "require_root"), patch.object(
            helper, "load_state", return_value=default_state()
        ), patch.object(
            helper, "resolve_domain_ips", return_value=["93.184.216.34"]
        ), patch.object(helper, "apply_transaction") as transaction:
            helper.add_entry({"target": "example.org", "category": "Manual", "smart": True})
            new_state = transaction.call_args.args[1]
            entry = new_state["entries"][0]
            self.assertTrue(entry["smart"])
            self.assertEqual(entry["resolved_ips"], ["93.184.216.34"])


class InternationalisationTests(unittest.TestCase):
    def test_default_and_all_languages_have_main_interface_strings(self):
        self.assertEqual(LANGUAGES["en"], "English (International)")
        required = {
            "app_subtitle",
            "setup_title",
            "login_title",
            "overview_title",
            "add_title",
            "adult_title",
            "list_title",
            "rules_tab",
            "squid_tab",
            "squid_title",
            "squid_description",
            "squid_keywords_title",
            "column_status",
            "blocked_status",
            "password_minimum",
            "password_ready",
            "browser_note",
            "about_text",
        }
        self.assertTrue(required.issubset(EN))
        for language in LANGUAGES:
            for key in required:
                with self.subTest(language=language, key=key):
                    self.assertNotEqual(tr(key, language), key)


class InterfaceDesignTests(unittest.TestCase):
    def test_version_and_subtle_3d_boxed_styles(self):
        stylesheet = SOURCE.parent / "assets" / "eduka-block.css"
        css = stylesheet.read_text(encoding="utf-8")

        interface = (SOURCE / "eduka_block.py").read_text(encoding="utf-8")

        self.assertEqual(APP_VERSION, "0.4.2")
        self.assertIn("box-shadow", css)
        self.assertNotIn("linear-gradient", css)
        self.assertNotIn("radial-gradient", css)
        for selector in (
            ".card",
            ".brand-box",
            ".section-title",
            ".field-label",
            ".text-box",
            ".info-box",
            ".hint-box",
            ".blocked-summary",
            ".password-status",
        ):
            with self.subTest(selector=selector):
                self.assertIn(selector, css)
        self.assertIn("self.set_default_size(900, 600)", interface)
        self.assertIn("self.set_size_request(700, 500)", interface)
        self.assertIn('T("squid_tab")', interface)
        self.assertIn("RESPONSE_CHANGE_ACCOUNT", interface)
        self.assertIn("blocked_renderer", interface)
        self.assertIn('T("blocked_status")', interface)
        self.assertIn("len(password) >= 5", interface)
        # Popover children only: show_all() on the popover pops it open at start-up.
        self.assertNotIn("popover.show_all()", interface)
        # Global widget rules would restyle popovers and native dialogs.
        for line in css.splitlines():
            if line.startswith(("button", "entry", "searchentry", "combobox", "switch", "treeview")):
                self.fail(f"unscoped control selector: {line}")


class SquidProxyTests(unittest.TestCase):
    def test_keyword_validation_is_literal_and_bounded(self):
        self.assertEqual(
            normalize_squid_keywords([" Porn ", "seks", "porn"]),
            ["porn", "seks"],
        )
        for invalid in (".*", "x", "http_access allow all", "porn\ninclude /tmp/bad"):
            with self.subTest(invalid=invalid), self.assertRaises(HelperError):
                normalize_squid_keywords([invalid])

    def test_renders_fixed_acl_and_generated_patterns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keywords_path = root / "keywords.txt"
            config_path = root / "eduka-block.conf"
            render_squid_keywords(["adult", "sex education"], keywords_path)
            render_squid_config(config_path)
            keywords = keywords_path.read_text(encoding="utf-8")
            config = config_path.read_text(encoding="utf-8")
            self.assertIn("\nadult\n", keywords)
            self.assertIn("sex[^a-z0-9]+education", keywords)
            self.assertIn("acl eduka_block_url url_regex -i", config)
            self.assertIn("acl eduka_block_domain dstdom_regex -i", config)
            self.assertIn("http_access deny !eduka_block_localhost", config)
            self.assertIn("http_access deny eduka_block_url", config)
            self.assertIn("http_port 127.0.0.1:3128", config)

    def test_include_is_inserted_before_allow_and_is_reversible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "squid.conf"
            backup = root / "squid.conf.backup"
            original = (
                "http_port 3128\n"
                "acl Safe_ports port 80\n"
                "http_access deny !Safe_ports\n"
                "http_access allow localhost\n"
                "http_access deny all\n"
            )
            main.write_text(original, encoding="utf-8")
            install_squid_include(main, backup)
            managed = main.read_text(encoding="utf-8")
            self.assertLess(managed.index(SQUID_BEGIN_MARKER), managed.index("http_access allow"))
            self.assertIn("# EDUKA-BLOCK ORIGINAL HTTP_PORT: http_port 3128", managed)
            self.assertNotIn("\nhttp_port 3128\n", managed)
            self.assertEqual(remove_squid_include(managed), original)
            self.assertEqual(backup.read_text(encoding="utf-8"), original)


class FirewallMergeTests(unittest.TestCase):
    def test_overlapping_ranges_and_addresses_are_collapsed(self):
        # nft interval sets reject overlapping elements, which previously made
        # the whole firewall update fail and roll back.
        state = default_state()
        state["entries"] = [
            {"value": "203.0.113.0/24", "kind": "ipv4_network"},
            {"value": "203.0.113.10", "kind": "ipv4"},
            {"value": "example.org", "kind": "domain", "smart": True,
             "resolved_ips": ["203.0.113.55", "198.51.100.7", "2001:db8::1"]},
            {"value": "2001:db8::/48", "kind": "ipv6_network"},
            {"value": "198.51.100.8", "kind": "ipv4"},
        ]
        ipv4, ipv6 = firewall_elements(state)
        self.assertEqual(ipv4, ["198.51.100.7", "198.51.100.8", "203.0.113.0/24"])
        self.assertEqual(ipv6, ["2001:db8::/48"])

    def test_adjacent_single_addresses_merge_into_range(self):
        state = default_state()
        state["entries"] = [
            {"value": "198.51.100.8", "kind": "ipv4"},
            {"value": "198.51.100.9", "kind": "ipv4"},
        ]
        self.assertEqual(firewall_elements(state)[0], ["198.51.100.8/31"])


class RuleManagementTests(unittest.TestCase):
    def entries(self):
        return [
            {"id": "a", "value": "example.org", "kind": "domain", "category": "Social"},
            {"id": "b", "value": "203.0.113.9", "kind": "ipv4", "category": "Manual"},
        ]

    def test_subdomain_already_covered_by_parent_rule(self):
        self.assertEqual(helper.covering_domain("video.example.org", self.entries()), "example.org")
        self.assertIsNone(helper.covering_domain("example.org", self.entries()))
        self.assertIsNone(helper.covering_domain("notexample.org", self.entries()))

    def test_add_rejects_covered_subdomain(self):
        state = default_state()
        state["entries"] = self.entries()
        with patch.object(helper, "require_root"), patch.object(
            helper, "load_state", return_value=state
        ), patch.object(helper, "apply_transaction") as transaction:
            with self.assertRaises(HelperError) as caught:
                helper.add_entry({"target": "https://cdn.example.org/x"})
        self.assertEqual(caught.exception.code, "err_covered")
        self.assertEqual(caught.exception.detail, "example.org")
        transaction.assert_not_called()

    def test_remove_many_rules_in_one_transaction(self):
        state = default_state()
        state["entries"] = self.entries()
        with patch.object(helper, "require_root"), patch.object(
            helper, "load_state", return_value=state
        ), patch.object(helper, "apply_transaction") as transaction:
            helper.remove_entry({"ids": ["a", "b"]})
            self.assertEqual(transaction.call_args.args[1]["entries"], [])
            transaction.reset_mock()
            helper.remove_entry({"id": "a"})  # 0.4.1 single-id payload still works
            self.assertEqual([e["id"] for e in transaction.call_args.args[1]["entries"]], ["b"])
            with self.assertRaises(HelperError):
                helper.remove_entry({"ids": ["missing"]})

    def test_import_adds_valid_new_rules_and_counts_the_rest(self):
        state = default_state()
        state["entries"] = self.entries()
        items = [
            {"target": "new.example", "category": "Gambling"},
            {"target": "www.example.org"},          # covered by example.org
            {"target": "203.0.113.9"},              # duplicate
            {"target": "localhost"},                # invalid
            {"target": "198.51.100.0/24", "category": "Bogus"},
            "not-a-dict",
        ]
        with patch.object(helper, "require_root"), patch.object(
            helper, "load_state", return_value=state
        ), patch.object(helper, "resolve_domain_ips") as resolve, patch.object(
            helper, "apply_transaction"
        ) as transaction:
            result = helper.import_entries({"items": items, "smart": True})
        resolve.assert_not_called()  # smart IPs are learned by the next sync
        self.assertEqual(result, {"added": 2, "skipped": 2, "invalid": 2})
        added = transaction.call_args.args[1]["entries"][2:]
        self.assertEqual([e["value"] for e in added], ["new.example", "198.51.100.0/24"])
        self.assertEqual(added[0]["category"], "Gambling")
        self.assertTrue(added[0]["smart"])
        self.assertEqual(added[1]["category"], "Other")
        self.assertFalse(added[1]["smart"])

    def test_import_limits(self):
        with patch.object(helper, "require_root"):
            with self.assertRaises(HelperError):
                helper.import_entries({"items": []})
            with self.assertRaises(HelperError):
                helper.import_entries({"items": [{"target": "a.example"}] * 1001})

    def test_export_then_parse_roundtrip(self):
        text = export_rules_text(self.entries())
        self.assertTrue(text.startswith("#"))
        self.assertEqual(
            parse_rules_text(text),
            [
                {"target": "203.0.113.9", "category": "Manual"},
                {"target": "example.org", "category": "Social"},
            ],
        )

    def test_parse_accepts_hosts_files_and_plain_lists(self):
        text = (
            "# comment line\n"
            "0.0.0.0 bad.example ads.example  # tracker list\n"
            "127.0.0.1 localhost\n"
            "https://plain.example/path\n"
            "bad.example\n"
        )
        items = parse_rules_text(text, "Harmful")
        self.assertEqual(
            [item["target"] for item in items],
            ["bad.example", "ads.example", "localhost", "https://plain.example/path"],
        )
        self.assertTrue(all(item["category"] == "Harmful" for item in items))


class SmartSyncTests(unittest.TestCase):
    def test_sync_merges_prepared_results_into_fresh_state(self):
        state = default_state()
        state["entries"] = [
            {"id": "a", "value": "example.org", "kind": "domain", "smart": True, "resolved_ips": []},
            {"id": "b", "value": "static.example", "kind": "domain", "smart": False, "resolved_ips": []},
        ]
        with patch.object(helper, "require_root"), patch.object(
            helper, "load_state", return_value=state
        ), patch.object(helper, "save_state") as save, patch.object(
            helper, "apply_firewall"
        ) as firewall:
            helper.sync_smart_ips({"example.org": ["93.184.216.34"], "gone.example": ["1.2.3.4"]})
        saved = save.call_args.args[0]
        self.assertEqual(saved["entries"][0]["resolved_ips"], ["93.184.216.34"])
        self.assertEqual(saved["entries"][1]["resolved_ips"], [])
        firewall.assert_called_once()

    def test_slow_network_work_happens_before_the_lock(self):
        with patch.object(helper, "require_root"), patch.object(
            helper, "download_adult_domains", return_value=["a.example"]
        ):
            self.assertEqual(helper.prepare("adult-update"), ["a.example"])
        self.assertIsNone(helper.prepare("add"))


class LockTests(unittest.TestCase):
    def test_lock_lives_in_root_only_directory(self):
        # /run/lock is world-writable; a user could pre-create and hold the lock.
        self.assertEqual(helper.LOCK_PATH.parent, Path("/run"))

    def test_lock_times_out_instead_of_waiting_forever(self):
        import fcntl

        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "test.lock"
            holder = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(holder, fcntl.LOCK_EX)
            try:
                with patch.object(helper, "LOCK_PATH", lock_path), patch.object(
                    helper, "LOCK_TIMEOUT_SECONDS", 0.3
                ), patch.object(helper, "require_root"):
                    with self.assertRaises(HelperError) as caught:
                        with helper.exclusive_system_lock():
                            pass
                self.assertEqual(caught.exception.code, "err_busy")
            finally:
                os.close(holder)


class TranslationCompletenessTests(unittest.TestCase):
    def test_every_language_translates_every_string(self):
        import string

        def placeholders(text):
            return {name for _, name, _, _ in string.Formatter().parse(text) if name}

        for language in LANGUAGES:
            chain = [TRANSLATIONS[language]]
            if language in FALLBACKS:
                chain.append(TRANSLATIONS[FALLBACKS[language]])
            for key, english in EN.items():
                with self.subTest(language=language, key=key):
                    translated = next((table[key] for table in chain if key in table), None)
                    self.assertIsNotNone(translated, "missing translation")
                    self.assertEqual(placeholders(translated), placeholders(english))

    def test_interface_uses_only_known_strings(self):
        import re

        interface = (SOURCE / "eduka_block.py").read_text(encoding="utf-8")
        for key in re.findall(r'\bT\(\s*"([a-z0-9_]+)"', interface):
            with self.subTest(key=key):
                self.assertIn(key, EN)

    def test_version_is_filled_automatically(self):
        self.assertIn(APP_VERSION, tr("app_subtitle", "tet"))
        self.assertIn(APP_VERSION, tr("about_text", "pt_BR"))


if __name__ == "__main__":
    unittest.main()
