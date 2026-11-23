"""Briefing rules from the 2026-11-23 review: every CVE of a multi-CVE issue is listed, and a changed
priority is explained (or the earlier one kept)."""
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_md():
    with open(os.path.join(REPO, "prompts", "run.md"), encoding="utf-8") as f:
        return f.read()


def news_section(text):
    return text.split("## 2. News (briefing)", 1)[1].split("## 3.", 1)[0]


class TestMultiCveItems(unittest.TestCase):
    """An item covering several CVEs (e.g. five nginx CVEs in one write-up) names all of them."""

    def test_rule_lists_every_cve_with_its_configuration(self):
        news = news_section(run_md())
        self.assertIn("**Several CVEs for one issue:**", news)
        self.assertIn("list every CVE, each with its affected configuration in a few words", news)
        self.assertIn("only as the source states them", news)

    def test_rule_sits_with_the_per_item_fields(self):
        news = news_section(run_md())
        self.assertLess(news.index("**Claims match the source:**"), news.index("**Several CVEs for one issue:**"))
        self.assertLess(news.index("**Several CVEs for one issue:**"), news.index("**Priority**"))


class TestPriorityChanges(unittest.TestCase):
    """A CVE reported 🔴 one day and 🟠 later says why, or keeps 🔴."""

    def test_changed_priority_is_marked_updated_with_a_reason(self):
        news = news_section(run_md())
        self.assertIn("An item or CVE reported earlier at another priority", news)
        self.assertIn("mark it UPDATED with the reason in a few words", news)
        self.assertIn("🔴 → 🟠: no exploitation reported; patch widely available", news)

    def test_no_reason_keeps_the_earlier_priority(self):
        self.assertIn("No reason: keep the earlier priority.", news_section(run_md()))

    def test_earlier_priority_comes_from_saved_state(self):
        # checks.json is read every run and keeps each check's severity, so an older report isn't needed.
        self.assertIn("(checks.json `severity`, earlier reports)", news_section(run_md()))
        self.assertIn('"severity"', open(os.path.join(REPO, "schema", "checks.schema.json"), encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
