"""Scanner bugs from the pre-promotion code review: RLS disabled in a later migration, several ranges
for one Python package, and Python manifests as audit inputs."""
import os
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE]

from test_p0_safety import realtmp  # noqa: E402
from occupai_scan.hygiene import check_db  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
