"""Briefing rules from the 2026-11-23 review: every CVE of a multi-CVE issue is listed."""
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


if __name__ == "__main__":
    unittest.main()
