"""Round 4: release readiness. Setup a stranger can follow, compact reports, docs that match what exists."""
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


class TestSetupRound4(unittest.TestCase):
    def setUp(self):
        self.s = read("SETUP.md")

    def test_stay_on_this_chat_and_ask_again(self):
        s = self.s
        stay = s.index("Stay on this chat for a moment")
        self.assertLess(stay, s.index("then request access"))
        self.assertIn("This often happens if you switched away. Reply **ask again**", s)

    def test_no_helper_tasks(self):
        s = self.s
        self.assertIn("Never start tasks or create helper or one-off tasks", s)
        self.assertNotIn("start the scan", s)
        self.assertNotIn("reminder", s.lower())

    def test_numbered_folder_list_in_two_groups(self):
        s = self.s
        for part in ("numbered list, one per line", "**Projects**",
                     "**Looks like a backup or copy, skipped unless you pick it**", '"all suggested"'):
            self.assertIn(part, s)

    def test_schedule_a_few_minutes_early(self):
        self.assertIn("07:52 for 08:00", self.s)
        for p in ("occupai.config.example.yaml", "occupai.config.yaml"):
            y = read(p)
            self.assertIn('briefing: "52 7 * * *"', y, p)
            self.assertIn('scan: "12 8 * * *"', y, p)
            self.assertNotIn("run:", y, p)


class TestReportsRound4(unittest.TestCase):
    def test_news_summary_first(self):
        run = read("prompts", "run.md")
        news = run[run.index("YYYY-MM-DD-news.md`**"):run.index("YYYY-MM-DD-projects.md`**")]
        self.assertLess(news.index("## Summary"), news.index("### 🔴 CRITICAL"))

    def test_chat_message_and_accuracy(self):
        run = read("prompts", "run.md")
        self.assertIn("Final message: copy this template. Nothing else: no paragraphs, no other file names.", run)
        self.assertIn("may still apply until <framework> ships a fix", run)
        self.assertIn("never a rule matching every version", run)
        self.assertIn("naming files as files (not folders)", run)

    def test_demo_news_has_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, os.path.join(REPO, "examples", "demo", "run_demo.py"), "--out", tmp],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            b = os.path.join(tmp, "storage", "briefings")
            news = read(b, next(f for f in os.listdir(b) if f.endswith("-news.md")))
            summary = news[news.index("## Summary"):news.index("### ")]
            lines = [ln for ln in summary.splitlines()[1:] if ln.strip()]
            self.assertTrue(lines)
            for ln in lines:
                self.assertRegex(ln, r"^- (🔴|🟠|🟡|⚪) \[[a-z0-9-]+\] .+ — .+")


class TestDocsMatchWhatExists(unittest.TestCase):
    DOCS = ["README.md", "SETUP.md", os.path.join("docs", "storage.md")] + [
        os.path.join("docs", "setup", f) for f in ("claude-desktop.md", "claude-code.md", "codex.md", "generic.md")]

    def test_no_leftovers(self):
        for p in self.DOCS:
            t = read(p).lower()
            self.assertNotRegex(t, r"three (scheduled )?(tasks|automations)", p)
            self.assertNotIn("one report", t, p)
            self.assertNotIn("combined report", t, p)
        readme = read("README.md")
        gone = "o" + "sv"  # spelled in two parts so the older no-route test doesn't match this file
        self.assertNotIn(gone, readme.lower().replace("dependabot, snyk or " + gone + "-scanner", ""))

    def test_tested_vs_untested(self):
        readme = read("README.md")
        self.assertIn("tested end to end on one Mac", readme)
        for guide in ("claude-code.md", "codex.md", "generic.md"):
            self.assertRegex(read("docs", "setup", guide), r"(?i)untested", guide)

    def test_changelog_release_entry(self):
        c = read("CHANGELOG.md")
        headings = re.findall(r"(?m)^## .*$", c)
        # the newest release is first, after an optional "Unreleased" section
        self.assertIn("0.1.0", headings[1] if headings[0] == "## Unreleased" else headings[0])


if __name__ == "__main__":
    unittest.main()
