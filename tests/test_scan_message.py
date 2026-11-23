"""Scan message and to-do list (2026-11-23): items the scan can't check are grouped under "Needs you",
after the project findings, and the message names what was scanned."""
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEEDS = "Needs you (outside what the scan can see)"


def run_md():
    with open(os.path.join(REPO, "prompts", "run.md"), encoding="utf-8") as f:
        return f.read()


def scan_template():
    return [b for b in re.findall(r"```\n(.*?)```", run_md(), re.S) if b.startswith("<Result line>")][0].splitlines()


def projects_template():
    return [b for b in re.findall(r"```\n(.*?)```", run_md(), re.S) if b.startswith("# OccupAI projects")][0]


class TestNeedsYou(unittest.TestCase):
    def test_message_lists_project_findings_first_unlabelled(self):
        lines = scan_template()
        label = lines.index(NEEDS + ":")
        self.assertTrue(any("<project>: action — Fix: <step>" in ln for ln in lines[:label]))
        self.assertIn("<your computer, account or dashboard>: action — Fix: <step>", lines[label + 1])
        self.assertIn("check-on-your-computer line", lines[label + 2])
        self.assertFalse(any("your computer" in ln for ln in lines[:label]))

    def test_report_section_comes_after_the_project_findings(self):
        t = projects_template()
        self.assertLess(t.index("## To do"), t.index("## " + NEEDS))
        self.assertLess(t.index("## " + NEEDS), t.index("## Not checked"))
        self.assertNotIn("## Check on your computer", t)

    def test_what_goes_there(self):
        run = run_md()
        self.assertIn("Items the scan can't check (your computer, GitHub or other online accounts, live dashboards "
                      'like Supabase) go only under "Needs you".', run)
        self.assertIn('"Needs you" only when it has items.', run)

    def test_demo_report_uses_it(self):
        with open(os.path.join(REPO, "examples", "demo", "run_demo.py"), encoding="utf-8") as f:
            demo = f.read()
        self.assertIn("## " + NEEDS, demo)
        self.assertNotIn("Check on your computer", demo)


class TestScannedLine(unittest.TestCase):
    def test_right_after_the_result_line(self):
        lines = scan_template()
        self.assertEqual(lines[0], "<Result line>")
        self.assertEqual(lines[1], "Scanned: <projects> · <managed/not-mine projects> (info only) · "
                                   "Not reachable: <projects or none>")

    def test_also_on_quiet_days(self):
        self.assertIn('"Scanned:" comes from `changed`, also on quiet days.', run_md())


if __name__ == "__main__":
    unittest.main()
