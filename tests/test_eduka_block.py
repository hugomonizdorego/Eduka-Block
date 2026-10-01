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
    rule_target,
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

REAL_APPLY_FIREWALL = helper.apply_firewall
REAL_DOWNLOAD_BLOCKLIST = helper.download_blocklist
REAL_LOCK_PATH = helper.LOCK_PATH
from eduka_block_i18n import EN, FALLBACKS, LANGUAGES, TRANSLATIONS, tr  # noqa: E402


class SandboxTestCase(unittest.TestCase):
    """Redirect every system path the helper touches into a temporary root.

    The suite may run as root (CI containers, packaging chroots); without this
    a test could rewrite the real /etc/hosts, browser policies or firewall.
    """

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "etc").mkdir()
        (self.root / "state").mkdir()
        self.hosts = self.root / "etc" / "hosts"
        self.hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        self.resolv = self.root / "etc" / "resolv.conf"
        self.resolv.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
        self.nm_config = self.root / "etc" / "90-eduka-block-dns.conf"
        self.chromium_dirs = (self.root / "chromium", self.root / "chrome")
        self.firefox = self.root / "firefox" / "policies.json"
        self.firewall_rulesets = []
        paths = {
            "STATE_DIR": self.root / "state",
            "STATE_PATH": self.root / "state" / "blocklist.json",
            "HOSTS_PATH": self.hosts,
            "HOSTS_BACKUP_PATH": self.root / "state" / "hosts.backup",
            "DNSMASQ_RULES_PATH": self.root / "dnsmasq" / "eduka-block.conf",
            "DNSMASQ_LISTS_PATH": self.root / "dnsmasq" / "eduka-block-lists.conf",
            "RESOLV_CONF_PATH": self.resolv,
            "NETWORKMANAGER_CONFIG": self.nm_config,
            "FIREFOX_POLICY_PATH": self.firefox,
            "FIREFOX_POLICY_BACKUP_PATH": self.root / "state" / "firefox.backup.json",
            "CHROMIUM_POLICY_DIRS": self.chromium_dirs,
            "LOCK_PATH": self.root / "eduka-block.lock",
            "APP_SHARE_DIR": self.root / "share",
            "CREDENTIALS_PATH": self.root / "share" / "credentials.txt",
        }
        stubs = {
            "require_root": lambda: None,
            "reload_dns_plugin": lambda full=True: True,
            "resolve_domain_ips": lambda domain, nameservers=None: [],
            "apply_firewall": lambda state: self.firewall_rulesets.append(
                helper.build_ruleset(state, False)
            ),
            "download_blocklist": self._no_download,
        }
        for name, value in {**paths, **stubs}.items():
            patcher = patch.object(helper, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _no_download(key):
        raise AssertionError(f"unexpected network download of {key}")


class ValidationTests(SandboxTestCase):
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

    def test_rules_drop_leading_www_so_wildcards_cover_the_site(self):
        self.assertEqual(rule_target("https://www.tiktok.com/@user"), ("tiktok.com", "domain"))
        self.assertEqual(rule_target("www.example.co.id"), ("example.co.id", "domain"))
        self.assertEqual(rule_target("www.com"), ("www.com", "domain"))
        self.assertEqual(rule_target("203.0.113.5"), ("203.0.113.5", "ipv4"))

    def test_aliases_only_common_pair(self):
        self.assertEqual(aliases_for_domain("example.org"), ["example.org", "www.example.org"])
        self.assertEqual(aliases_for_domain("www.example.org"), ["example.org", "www.example.org"])
        self.assertEqual(aliases_for_domain("school.example.org"), ["school.example.org"])


class CredentialTests(SandboxTestCase):
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


class HostsTests(SandboxTestCase):
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
            render_hosts(state, hosts, backup, list_domains=set())
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


class StateTests(SandboxTestCase):
    def test_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = default_state()
            save_state(state, path)
            self.assertEqual(load_state(path), state)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schema"], 4)

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
        self.assertEqual(migrated["schema"], 4)
        self.assertTrue(migrated["entries"][0]["smart"])
        self.assertEqual(migrated["entries"][0]["resolved_ips"], [])
        self.assertFalse(migrated["squid_proxy"]["enabled"])
        self.assertIn("porn", migrated["squid_proxy"]["keywords"])
        self.assertNotIn("adult_protection", migrated)
        self.assertEqual(set(migrated["lists"]), {"adult", "gambling", "social", "malware"})
        self.assertTrue(migrated["strict_mode"]["enabled"])

    def test_migrates_enabled_adult_list_from_schema_3(self):
        old = default_state()
        old["schema"] = 3
        del old["lists"], old["strict_mode"]
        old["adult_protection"] = {"enabled": True, "domain_count": 76000, "updated_at": "2026-09-01T00:00:00+00:00"}
        migrated = migrate_state(old)
        self.assertEqual(
            migrated["lists"]["adult"],
            {"enabled": True, "domain_count": 76000, "updated_at": "2026-09-01T00:00:00+00:00"},
        )
        self.assertFalse(migrated["lists"]["gambling"]["enabled"])
        self.assertEqual(helper.list_path("adult").name, "adult-domains.txt")

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
        state["strict_mode"]["enabled"] = False
        with patch.object(helper, "apply_firewall", REAL_APPLY_FIREWALL), patch.object(
            helper, "nft_binary", return_value="/usr/sbin/nft"
        ), patch.object(
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


class InternationalisationTests(SandboxTestCase):
    def test_default_and_all_languages_have_main_interface_strings(self):
        self.assertEqual(LANGUAGES["en"], "English (International)")
        required = {
            "brand_tagline",
            "nav_dashboard",
            "nav_websites",
            "nav_categories",
            "nav_advanced",
            "hero_strong",
            "hero_weak",
            "turn_on_recommended",
            "strict_title",
            "list_adult_title",
            "list_social_text",
            "setup_title",
            "login_title",
            "squid_title",
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


class InterfaceDesignTests(SandboxTestCase):
    def test_version_and_modern_scoped_styles(self):
        css = (SOURCE.parent / "assets" / "eduka-block.css").read_text(encoding="utf-8")
        interface = (SOURCE / "eduka_block.py").read_text(encoding="utf-8")

        self.assertEqual(APP_VERSION, "0.5.1")
        for selector in (".sidebar", ".nav-button", ".hero", ".card", ".toggle-row", ".toast", ".pill", ".chip"):
            with self.subTest(selector=selector):
                self.assertIn(selector, css)
        # Every rule is scoped so popovers and native dialogs keep the system theme.
        for line in css.splitlines():
            stripped = line.strip()
            if stripped.endswith(("{", ",")) and not stripped.startswith(("/*", "*", "@")):
                with self.subTest(selector=stripped):
                    self.assertTrue(stripped.startswith((".eduka-window", ".auth-dialog")))
        self.assertIn("self.set_default_size(980, 660)", interface)
        self.assertIn("self.set_size_request(760, 540)", interface)
        for page in ("dashboard", "websites", "categories", "advanced"):
            self.assertIn(f'("{page}", self.build_{page})', interface)
        self.assertIn('"protection-configure"', interface)
        self.assertIn("RECOMMENDED_LISTS", interface)
        self.assertIn("RESPONSE_CHANGE_ACCOUNT", interface)
        self.assertIn("blocked_renderer", interface)
        self.assertIn('T("blocked_status")', interface)
        self.assertIn("len(password) >= 5", interface)
        self.assertNotIn("popover.show_all()", interface)


class SquidProxyTests(SandboxTestCase):
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


class FirewallMergeTests(SandboxTestCase):
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


class RuleManagementTests(SandboxTestCase):
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


class SmartSyncTests(SandboxTestCase):
    def test_sync_merges_prepared_results_into_fresh_state(self):
        state = default_state()
        state["dns_mode"] = "hosts"
        state["entries"] = [
            {"id": "a", "value": "example.org", "kind": "domain", "smart": True, "resolved_ips": []},
            {"id": "b", "value": "static.example", "kind": "domain", "smart": False, "resolved_ips": []},
        ]
        save_state(state)
        helper.sync_smart_ips({"example.org": ["93.184.216.34"], "gone.example": ["1.2.3.4"]}, {}, {})
        saved = load_state()
        self.assertEqual(saved["entries"][0]["resolved_ips"], ["93.184.216.34"])
        self.assertEqual(saved["entries"][1]["resolved_ips"], [])
        self.assertEqual(len(self.firewall_rulesets), 1)
        self.assertIn("93.184.216.34", self.firewall_rulesets[0])
        self.assertNotIn("EDUKA", self.hosts.read_text(encoding="utf-8"))  # no full apply needed

    def test_sync_moves_lists_when_dnsmasq_becomes_the_resolver(self):
        state = default_state()
        state["dns_mode"] = "hosts"
        state["lists"]["adult"].update(enabled=True, domain_count=1)
        save_state(state)
        helper.list_path("adult").write_text("adult.example\n", encoding="utf-8")
        self.nm_config.write_text("[main]\ndns=dnsmasq\n", encoding="utf-8")
        self.resolv.write_text("nameserver 127.0.0.1\n", encoding="utf-8")
        helper.sync_smart_ips({}, {}, {})
        self.assertEqual(load_state()["dns_mode"], "dnsmasq")
        self.assertNotIn("adult.example", self.hosts.read_text(encoding="utf-8"))
        self.assertIn("address=/adult.example/", helper.DNSMASQ_LISTS_PATH.read_text(encoding="utf-8"))

    def test_sync_refreshes_stale_lists_and_safe_search_addresses(self):
        state = default_state()
        state["lists"]["gambling"].update(enabled=True, domain_count=1, updated_at="2020-01-01T00:00:00+00:00")
        state["lists"]["adult"].update(enabled=True, domain_count=1, updated_at=helper.now_iso())
        save_state(state)
        downloads = []
        with patch.object(helper, "download_blocklist", lambda key: downloads.append(key) or ["bet.example"]):
            prepared = helper.prepare_sync(load_state())
        self.assertEqual(downloads, ["gambling"])  # adult is fresh
        helper.sync_smart_ips(prepared["domains"], {"forcesafesearch.google.com": ["216.239.38.120"]}, prepared["lists"])
        saved = load_state()
        self.assertEqual(saved["lists"]["gambling"]["domain_count"], 1)
        self.assertNotEqual(saved["lists"]["gambling"]["updated_at"], "2020-01-01T00:00:00+00:00")
        self.assertEqual(saved["strict_mode"]["safe_ips"], {"forcesafesearch.google.com": ["216.239.38.120"]})
        self.assertIn("0.0.0.0 bet.example", self.hosts.read_text(encoding="utf-8"))

    def test_slow_network_work_happens_before_the_lock(self):
        with patch.object(helper, "download_blocklist", return_value=["a.example"]) as download:
            prepared = helper.prepare("adult-update")
        self.assertEqual(prepared["lists"], {"adult": ["a.example"]})
        download.assert_called_once_with("adult")
        self.assertIsNone(helper.prepare("add", {}))


class ProtectionLayerTests(SandboxTestCase):
    def state_with_lists(self):
        state = default_state()
        state["entries"] = [
            {"id": "a", "value": "youtube.com", "kind": "domain", "category": "Social", "smart": False},
        ]
        state["lists"]["adult"].update(enabled=True, domain_count=2)
        helper.list_path("adult").write_text("adult.example\nxxx.example\n", encoding="utf-8")
        return state

    def test_hosts_mode_writes_lists_safesearch_and_doh_blocks(self):
        state = self.state_with_lists()
        helper.apply_system(state)
        hosts = self.hosts.read_text(encoding="utf-8")
        self.assertIn("0.0.0.0 adult.example", hosts)
        self.assertNotIn(":: adult.example", hosts)  # category lists: one line per domain
        self.assertIn("216.239.38.120 www.google.com", hosts)
        self.assertIn("216.239.38.120 www.google.tl", hosts)
        self.assertIn("204.79.197.220 www.bing.com", hosts)
        self.assertIn("0.0.0.0 dns.google", hosts)
        # A blocked site must never be re-opened by its SafeSearch address.
        self.assertNotIn("www.youtube.com", hosts.replace("0.0.0.0 www.youtube.com", "").replace(":: www.youtube.com", ""))
        dnsmasq = helper.DNSMASQ_RULES_PATH.read_text(encoding="utf-8")
        self.assertIn("address=/use-application-dns.net/", dnsmasq)
        self.assertIn("address=/cloudflare-dns.com/0.0.0.0", dnsmasq)
        self.assertFalse(helper.DNSMASQ_LISTS_PATH.exists())

    def test_dnsmasq_mode_keeps_lists_out_of_etc_hosts(self):
        self.nm_config.write_text("[main]\ndns=dnsmasq\n", encoding="utf-8")
        self.resolv.write_text("# Generated by NetworkManager\nnameserver 127.0.0.1\n", encoding="utf-8")
        state = self.state_with_lists()
        self.assertEqual(helper.apply_system(state), "dnsmasq")
        self.assertNotIn("adult.example", self.hosts.read_text(encoding="utf-8"))
        lists = helper.DNSMASQ_LISTS_PATH.read_text(encoding="utf-8")
        self.assertIn("address=/adult.example/\n", lists)
        self.assertIn("address=/xxx.example/", lists)

    def test_strict_mode_off_removes_every_strict_layer(self):
        state = self.state_with_lists()
        helper.apply_system(state)
        state["strict_mode"]["enabled"] = False
        helper.apply_system(state)
        hosts = self.hosts.read_text(encoding="utf-8")
        self.assertNotIn("www.google.com", hosts)
        self.assertNotIn("dns.google", hosts)
        self.assertNotIn("use-application-dns.net", helper.DNSMASQ_RULES_PATH.read_text(encoding="utf-8"))
        self.assertFalse(any((d / "eduka-block.json").exists() for d in self.chromium_dirs))
        self.assertFalse(self.firefox.exists())
        self.assertNotIn("dport 853", self.firewall_rulesets[-1])

    def test_strict_firewall_blocks_encrypted_dns_only(self):
        state = default_state()
        ruleset = helper.build_ruleset(state, False)
        self.assertIn("th dport 853 drop", ruleset)
        self.assertIn("ip daddr @doh_ipv4 meta l4proto { tcp, udp } th dport 443 drop", ruleset)
        self.assertNotIn("dport 53 ", ruleset)  # plain DNS keeps working
        state["strict_mode"]["enabled"] = False
        self.assertEqual(helper.build_ruleset(state, False), "")
        self.assertEqual(helper.build_ruleset(state, True), "delete table inet eduka_block\n")

    def test_chromium_policies_disable_doh_and_force_safesearch(self):
        helper.apply_browser_policies(default_state())
        for directory in self.chromium_dirs:
            policy = json.loads((directory / "eduka-block.json").read_text(encoding="utf-8"))
            self.assertEqual(policy["DnsOverHttpsMode"], "off")
            self.assertTrue(policy["ForceGoogleSafeSearch"])

    def test_firefox_policy_merge_keeps_and_restores_admin_settings(self):
        self.firefox.parent.mkdir(parents=True)
        original = {"policies": {"DisableTelemetry": True, "DNSOverHTTPS": {"Enabled": True}}}
        self.firefox.write_text(json.dumps(original), encoding="utf-8")
        helper.apply_firefox_policy(True)
        merged = json.loads(self.firefox.read_text(encoding="utf-8"))
        self.assertTrue(merged["policies"]["DisableTelemetry"])
        self.assertEqual(merged["policies"]["DNSOverHTTPS"], {"Enabled": False, "Locked": True})
        helper.apply_firefox_policy(True)  # idempotent: the first backup is kept
        helper.apply_firefox_policy(False)
        self.assertEqual(json.loads(self.firefox.read_text(encoding="utf-8")), original)

    def test_firefox_policy_file_created_by_us_is_removed(self):
        helper.apply_firefox_policy(True)
        self.assertTrue(self.firefox.exists())
        helper.apply_firefox_policy(False)
        self.assertFalse(self.firefox.exists())

    def test_broken_browser_policy_does_not_block_other_layers(self):
        self.firefox.parent.mkdir(parents=True)
        self.firefox.write_text("{ not json", encoding="utf-8")
        state = default_state()
        state["entries"] = [{"id": "x", "value": "bad.example", "kind": "domain", "smart": False}]
        helper.apply_system(state)
        self.assertIn("0.0.0.0 bad.example", self.hosts.read_text(encoding="utf-8"))
        self.assertEqual(self.firefox.read_text(encoding="utf-8"), "{ not json")

    def test_configure_protection_enables_lists_and_strict_in_one_step(self):
        save_state(default_state())
        prepared = {"lists": {"adult": ["a.example"], "gambling": ["bet.example"]}, "safe_ips": {}}
        helper.configure_protection(
            {"lists": {"adult": True, "gambling": True, "malware": False}, "strict": True}, prepared
        )
        state = load_state()
        self.assertTrue(state["lists"]["adult"]["enabled"])
        self.assertEqual(state["lists"]["gambling"]["domain_count"], 1)
        hosts = self.hosts.read_text(encoding="utf-8")
        self.assertIn("0.0.0.0 bet.example", hosts)
        status = helper.public_status()
        self.assertEqual(status["list_domain_count"], 2)
        self.assertTrue(status["strict_mode"]["enabled"])
        self.assertTrue(status["browser_policies"])

    def test_configure_protection_rolls_back_list_files_on_failure(self):
        save_state(default_state())
        helper.list_path("adult").write_text("old.example\n", encoding="utf-8")

        def broken_firewall(state):
            raise HelperError("err_firewall", "boom")

        with patch.object(helper, "apply_firewall", broken_firewall), self.assertRaises(HelperError):
            helper.configure_protection({"lists": {"adult": True}}, {"lists": {"adult": ["new.example"]}})
        self.assertEqual(helper.list_path("adult").read_text(encoding="utf-8"), "old.example\n")
        self.assertFalse(load_state()["lists"]["adult"]["enabled"])

    def test_configure_rejects_unknown_lists(self):
        with self.assertRaises(HelperError):
            helper.configure_protection({"lists": {"everything": True}}, {"lists": {}})

    def test_list_integrity_bounds(self):
        small = "0.0.0.0 " + " ".join(f"d{n}.example" for n in range(150))
        self.assertEqual(len(parse_hosts_download(small, min_domains=100)), 150)
        with self.assertRaises(HelperError):
            parse_hosts_download(small, min_domains=1000)

    def test_detect_dns_mode_requires_local_dnsmasq_resolver(self):
        self.assertEqual(helper.detect_dns_mode(), "hosts")
        self.nm_config.write_text("[main]\ndns=dnsmasq\n", encoding="utf-8")
        self.assertEqual(helper.detect_dns_mode(), "hosts")
        self.resolv.write_text("nameserver 127.0.0.1\n", encoding="utf-8")
        self.assertEqual(helper.detect_dns_mode(), "dnsmasq")


class AccountRecoveryTests(SandboxTestCase):
    def test_account_info_reveals_username_only_to_root(self):
        self.assertEqual(helper.account_info(), {"username": ""})
        helper.setup_credentials({"username": "Profesór Ana", "password": "abcde"})
        self.assertEqual(helper.account_info(), {"username": "Profesór Ana"})
        self.assertNotIn("abcde", helper.CREDENTIALS_PATH.read_text(encoding="utf-8"))
        with patch.object(helper, "require_root", side_effect=HelperError("err_root")):
            with self.assertRaises(HelperError):
                helper.account_info()

    def test_reset_replaces_password_and_keeps_rules(self):
        state = default_state()
        state["entries"] = [{"id": "x", "value": "bad.example", "kind": "domain", "smart": False}]
        save_state(state)
        helper.setup_credentials({"username": "teacher", "password": "old-pass"})
        helper.dispatch("change-credentials", {"username": "teacher", "password": "new-pass"})
        self.assertTrue(verify_credentials("teacher", "new-pass", helper.CREDENTIALS_PATH))
        self.assertFalse(verify_credentials("teacher", "old-pass", helper.CREDENTIALS_PATH))
        self.assertEqual(load_state()["entries"][0]["value"], "bad.example")
        self.assertEqual(
            helper.dispatch("account-info", {})["account"], {"username": "teacher"}
        )

    def test_terminal_reset_tool(self):
        import eduka_block_reset as reset

        path = self.root / "share" / "credentials.txt"
        reset.write_credentials("guru", "secret", path)
        self.assertEqual(reset.stored_username(path), "guru")
        self.assertTrue(verify_credentials("guru", "secret", path))
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o644")
        with self.assertRaises(ValidationError):
            reset.write_credentials("guru", "1234", path)
        with patch.object(reset.os, "geteuid", return_value=1000):
            self.assertEqual(reset.main(["--show-username"]), 1)


class LockTests(SandboxTestCase):
    def test_lock_lives_in_root_only_directory(self):
        # /run/lock is world-writable; a user could pre-create and hold the lock.
        self.assertEqual(REAL_LOCK_PATH.parent, Path("/run"))

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


class TranslationCompletenessTests(SandboxTestCase):
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
        keys = set(re.findall(r'\bT\(\s*"([a-z0-9_]+)"', interface))
        # Keys handed to helpers such as page_header(), toggle_row() and run_helper().
        keys |= set(re.findall(r'"((?:nav|layer|stat|hero|strict|websites|categories|advanced)_[a-z_]+)"', interface))
        keys.discard("strict_mode")  # a status field, not a string
        from eduka_block_data import BLOCKLISTS

        for name in BLOCKLISTS:
            keys |= {f"list_{name}_title", f"list_{name}_text"}
        self.assertEqual(sorted(key for key in keys if key not in EN), [])

    def test_version_is_filled_automatically(self):
        self.assertIn(APP_VERSION, tr("brand_tagline", "tet"))
        self.assertIn(APP_VERSION, tr("about_text", "pt_BR"))


if __name__ == "__main__":
    unittest.main()
