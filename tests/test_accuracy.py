"""Issue 23: briefing claims match the fetched source (attribution, numbers, exploited, malicious), with a
verify step before the news brief is saved and a "Verified" line under "Sources checked"."""
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


class TestClaimsMatchSource(unittest.TestCase):
    def setUp(self):
        self.run = read("prompts", "run.md")
        self.news = self.run.split("## 2. News")[1].split("## 3.")[0]

    def test_item_rule_limits_claims_to_the_source(self):
        self.assertIn('- **Claims match the source:** attribution (country, group), victim and impact numbers,'
                      ' "actively exploited" and "malicious" only as the fetched source states them. If it doesn\'t'
                      ' say it, leave it out or write "the source doesn\'t attribute it".', self.news)
        # it is a per-item rule, next to the quote rule
        items = self.news.split("Per new item")[1].split("**Quick match")[0]
        self.assertLess(items.index("verbatim quote"), items.index("**Claims match the source:**"))

    def test_verify_step_before_saving(self):
        verify = self.news.split("**Verify before saving the news brief:**")[1].split("\n\n")[0]
        for part in ("each 🔴 and 🟠 item's headline and fix line against its source",
                     "versions, package names, attribution, numbers, exploited status, dates",
                     "change anything unsupported to match the source, or remove it",
                     "A 🔴 item calling a package or release malicious: re-open its primary source once"
                     " to confirm names and versions",
                     'if it can\'t be fetched, write "not re-confirmed" in the item'):
            self.assertIn(part, verify)
        # the verify step runs in briefing mode, before step 5 writes the report
        self.assertLess(self.run.index("**Verify before saving"), self.run.index("## 5. Two reports"))

    def test_verified_line_in_sources_checked(self):
        brief = self.run.split("**`STORAGE/briefings/YYYY-MM-DD-news.md`**")[1].split("```")[1]
        lines = brief.strip().splitlines()
        i = next(n for n, ln in enumerate(lines) if ln.startswith("Sources checked:"))
        self.assertEqual(lines[i + 1], "Verified: N items checked against sources, M corrected.")
        self.assertNotIn("Verified:", self.run.split("**`STORAGE/briefings/YYYY-MM-DD-projects.md`**")[1])


if __name__ == "__main__":
    unittest.main()
