"""Scanner bugs from the pre-promotion code review: RLS disabled in a later migration, several ranges
for one Python package, and Python manifests as audit inputs."""
import json
import os
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE]

from test_p0_safety import realtmp  # noqa: E402
from occupai_scan.hygiene import check_db  # noqa: E402
from occupai_scan.match import run_match  # noqa: E402
from occupai_scan.safefs import Policy  # noqa: E402


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class TmpRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-review-")
        self.root = os.path.join(self.tmp, "projects")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.root, *parts)


class TestRlsDisabledLater(TmpRoot):
    """Row level security enabled in one migration and disabled in a later one leaves the table open."""

    def migrations(self, *files):
        write(self.p("supa", "package.json"), '{"dependencies": {"@supabase/supabase-js": "2.0.0"}}')
        for name, sql in files:
            write(self.p("supa", "supabase", "migrations", name), sql)
        r = check_db(Policy(self.root).for_unit("supa"), "supa")
        return {f["table"]: f["type"] for f in r["findings"] if "table" in f}

    def test_disable_in_a_later_migration_is_a_finding(self):
        found = self.migrations(
            ("0001_init.sql", "create table public.notes (id int);\n"
                              "alter table public.notes enable row level security;\n"
                              "create policy own on public.notes for select using (true);\n"),
            ("0002_open.sql", "alter table public.notes disable row level security;\n"))
        self.assertEqual(found, {"notes": "supabase-table-without-rls"})

    def test_last_statement_wins_across_and_within_files(self):
        found = self.migrations(
            ("0001_init.sql", "create table a (id int); create table b (id int);\n"
                              "alter table a disable row level security; alter table a enable row level security;\n"
                              "create policy p on a using (true); create policy p on b using (true);\n"),
            ("0002_toggle.sql", "alter table b enable row level security;\n"),
            ("0003_toggle.sql", "alter table only public.b disable row level security;\n"
                                "alter table b enable row level security;\n"))
        self.assertEqual(found, {})

    def test_order_is_by_path_not_listing(self):
        # 0010 sorts after 0002; a disable in 0002 is undone by the enable in 0010.
        found = self.migrations(
            ("0010_fix.sql", "alter table c enable row level security;\ncreate policy p on c using (true);\n"),
            ("0002_open.sql", "create table c (id int);\nalter table c disable row level security;\n"))
        self.assertEqual(found, {})


class TestSeveralRangesForOnePackage(TmpRoot):
    """A check with two ranges for one package matches a version in either range."""

    def match(self, files, packages):
        for f, text in files.items():
            write(self.p("app", f), text)
        check = {"id": "two-ranges", "scope": "project", "match": {"packages": packages}}
        return run_match(Policy(self.root), ["app"], [check])["two-ranges"]["projects"]["app"]["status"]

    def test_pypi_first_range_still_matches(self):
        rules = [{"name": "requests", "ecosystem": "pypi", "affected": ">=1.0 <2.0"},
                 {"name": "Requests", "ecosystem": "pypi", "affected": ">=3.0 <4.0"}]
        self.assertEqual(self.match({"requirements.txt": "requests==1.5.0\n"}, rules), "open")
        self.assertEqual(self.match({"requirements.txt": "requests==3.5.0\n"}, rules), "open")
        self.assertEqual(self.match({"requirements.txt": "requests==2.5.0\n"}, rules), "not-affected")

    def test_npm_first_range_still_matches(self):
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/left-pad": {"version": "1.5.0"}}}
        rules = [{"name": "left-pad", "affected": ">=1.0.0 <2.0.0"}, {"name": "left-pad", "affected": ">=3.0.0 <4.0.0"}]
        self.assertEqual(self.match({"package.json": '{"name": "app"}', "package-lock.json": json.dumps(lock)},
                                    rules), "open")


if __name__ == "__main__":
    unittest.main()
