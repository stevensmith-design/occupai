"""Round 7 (fresh-install test 3): setup attaches the approved folder, never starts tasks."""
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


class TestSetupRound7(unittest.TestCase):
    def setUp(self):
        s = read("SETUP.md")
        self.sched = s.split("## 6.")[1].split("## 7.")[0]
        self.setup = s

    def test_attach_the_approved_folder_only(self):
        sched = self.sched
        self.assertIn("Attach exactly the folders approved in step 3: `projects_root`, plus KIT if outside it.", sched)
        self.assertIn("Never attach individual projects, even if only some are watched: exclusions handle that,"
                      " and new projects are picked up automatically.", sched)

    def test_agent_never_starts_tasks(self):
        sched = self.sched
        self.assertIn("Never start tasks or create helper or one-off tasks", sched)
        self.assertIn('"Run the first check now? (Recommended, about 10–20 minutes.) Open OccupAI briefing in your'
                      ' scheduled tasks and run it now. When its notification arrives, run OccupAI scan the same way.'
                      ' Or skip it, and it runs tomorrow at <briefing time>."', sched)
        self.assertIn("choose 'always allow'", sched)
        for gone in ("Run each once", "Then run each once now", "marker wait", "start the scan", "Start the briefing"):
            self.assertNotIn(gone, self.setup)

    def test_readme_and_guide_match(self):
        readme = read("README.md")
        self.assertNotIn("runs each once while you're there", readme)
        self.assertIn("You start each task once yourself to approve its access", readme)
        self.assertNotIn("a first run of each while you're there", read("docs", "setup", "claude-desktop.md"))


class TestFinalMessageTemplates(unittest.TestCase):
    def setUp(self):
        self.finish = read("prompts", "run.md").split("## 6. Finish")[1]
        self.blocks = [b.splitlines() for b in self.finish.split("```\n")[1::2]]

    def test_rules_for_both(self):
        f = self.finish
        self.assertIn("Final message: copy this mode's template. Nothing else: no paragraphs, no other file names.", f)
        self.assertIn("If your tool can attach files in the chat (e.g. a file card), attach the report; otherwise give its path.", f)
        self.assertEqual(len(self.blocks), 2)

    def test_briefing_template(self):
        self.assertEqual(self.blocks[0], [
            "N new items · X may affect your projects → to-do list comes with the scan",
            "🔴 [ID] headline (may affect: <project>)",
            "🟠 [ID] headline",
            "Report: briefings/DATE-news.md",
        ])
        self.assertNotIn("fix", " ".join(self.blocks[0]).lower())
        f = self.finish
        self.assertIn("Briefing: news only, no actions or fixes; up to ~10 headlines, most urgent first;", f)
        self.assertIn('"(may affect: …)" only where the quick match matched a project.', f)
        self.assertIn('Scorecard off: line 1 is "N new items", no "(may affect)".', f)

    def test_scan_template(self):
        self.assertEqual(self.blocks[1], [
            "<Result line>",
            "🔴 [ID] <project>: action — Fix: <step>",
            "Needs you (outside what the scan can see):",
            "🟠 [ID] <your computer, account or dashboard>: action — Fix: <step>",
            "<check-on-your-computer line, if machine items are open>",
            "To-do list: briefings/DATE-projects.md",
        ])
        f = self.finish
        self.assertIn('Scan: every checkbox line of the to-do list, grouped by marker, up to ~12, then "N more in the to-do list";', f)
        self.assertIn("<step> is howto.md's action line (\"open <project> in Claude Code and say: …\" or \"say 'how do I …?'\")", f)
        self.assertNotIn("Reports: briefings/DATE-news.md · briefings/DATE-projects.md", f)


if __name__ == "__main__":
    unittest.main()
