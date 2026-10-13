"""Проверки без сети и серверов: логика snihunt.py, скилл, инсталлятор."""
import importlib.util
import ipaddress
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_DIR = os.path.join(ROOT, "skills", "snishka")
SCRIPT = os.path.join(SKILL_DIR, "scripts", "snihunt.py")
SUBCOMMANDS = ["prefixes", "scan", "certs", "qualify", "rutest", "domains", "serve", "report"]

spec = importlib.util.spec_from_file_location("snihunt", SCRIPT)
snihunt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snihunt)


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class ProximityTest(unittest.TestCase):
    HOST = "203.0.113.10"
    NETS = [ipaddress.ip_network("198.51.100.0/24")]

    def classify(self, resolved, prefixes=NETS):
        with mock.patch.object(snihunt, "_resolve_ips", return_value=resolved):
            return snihunt._classify_proximity("example.test", self.HOST, prefixes, 1)[0]

    def test_same_ip(self):
        self.assertEqual(self.classify([self.HOST]), snihunt.PROX_SAME_IP)

    def test_same_24(self):
        self.assertEqual(self.classify(["203.0.113.77"]), snihunt.PROX_SAME_24)

    def test_same_asn(self):
        self.assertEqual(self.classify(["198.51.100.5"]), snihunt.PROX_SAME_ASN)

    def test_offnet(self):
        self.assertEqual(self.classify(["192.0.2.1"]), snihunt.PROX_OFFNET)

    def test_no_dns(self):
        self.assertEqual(self.classify([]), snihunt.PROX_NODNS)

    def test_without_prefixes_other_network_is_offnet(self):
        self.assertEqual(self.classify(["198.51.100.5"], prefixes=[]), snihunt.PROX_OFFNET)

    def test_rank_orders_closest_first(self):
        order = [snihunt.PROX_SAME_IP, snihunt.PROX_SAME_24, snihunt.PROX_SAME_ASN,
                 snihunt.PROX_OFFNET, snihunt.PROX_NODNS]
        ranks = [snihunt.PROX_RANK[p] for p in order]
        self.assertEqual(ranks, sorted(ranks))


class LoadPrefixesTest(unittest.TestCase):
    def test_skips_comments_blanks_and_garbage(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# комментарий\n\n10.0.0.0/8\nмусор\n192.0.2.0/24\n")
        try:
            nets = snihunt._load_prefixes(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual([str(n) for n in nets], ["10.0.0.0/8", "192.0.2.0/24"])

    def test_no_path_gives_empty(self):
        self.assertEqual(snihunt._load_prefixes(None), [])


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True,
                              text=True, timeout=30)

    def test_top_level_help(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)

    def test_each_subcommand_help(self):
        for cmd in SUBCOMMANDS:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.run_cli(cmd, "--help").returncode, 0)


class SkillTest(unittest.TestCase):
    def setUp(self):
        self.text = read("skills", "snishka", "SKILL.md")
        m = re.match(r"---\n(.*?)\n---\n", self.text, re.S)
        self.assertIsNotNone(m, "нет frontmatter")
        self.front = m.group(1)

    def test_name_matches_directory(self):
        m = re.search(r"^name:\s*(\S+)\s*$", self.front, re.M)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), os.path.basename(SKILL_DIR))

    def test_has_description(self):
        self.assertRegex(self.front, r"(?m)^description:")

    def test_not_model_invocable(self):
        self.assertRegex(self.front, r"(?m)^disable-model-invocation:\s*true\s*$")


class DocsTest(unittest.TestCase):
    # флаги внешних утилит (curl, openssl, cswap и т.п.), которых нет в snihunt.py
    EXTERNAL = {"--http2", "--resolve", "--help", "--version"}

    def test_documented_flags_exist_in_script(self):
        source = read("skills", "snishka", "scripts", "snihunt.py")
        docs = [read("skills", "snishka", "SKILL.md"), read("USAGE.md"), read("USAGE.en.md")]
        for text in docs:
            for flag in set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]+", text)):
                if flag in self.EXTERNAL:
                    continue
                with self.subTest(flag=flag):
                    self.assertIn(flag, source)

    def test_usage_ru_en_have_same_section_count(self):
        count = lambda t: len(re.findall(r"(?m)^## ", t))
        self.assertEqual(count(read("USAGE.md")), count(read("USAGE.en.md")))

    def test_readme_ru_en_have_same_section_count(self):
        count = lambda t: len(re.findall(r"(?m)^## ", t))
        self.assertEqual(count(read("README.md")), count(read("README.en.md")))


class InstallTest(unittest.TestCase):
    def install(self, home):
        env = dict(os.environ, HOME=home, USERPROFILE=home)
        return subprocess.run(["node", os.path.join(ROOT, "bin", "install.js")], env=env,
                              capture_output=True, text=True, timeout=30)

    def test_install_is_idempotent_and_copies_skill(self):
        with tempfile.TemporaryDirectory() as home:
            for _ in range(2):
                r = self.install(home)
                self.assertEqual(r.returncode, 0, r.stderr)
            dest = os.path.join(home, ".claude", "skills", "snishka")
            self.assertTrue(os.path.isfile(os.path.join(dest, "SKILL.md")))
            self.assertTrue(os.path.isfile(os.path.join(dest, "scripts", "snihunt.py")))


if __name__ == "__main__":
    unittest.main()
