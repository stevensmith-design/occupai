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
        self.assertIn("asks whether to run the first check now", readme)
        self.assertNotIn("a first run of each while you're there", read("docs", "setup", "claude-desktop.md"))


class TestFinalMessageTemplate(unittest.TestCase):
    def test_literal_template_for_both_modes(self):
        run = read("prompts", "run.md")
        finish = run.split("## 6. Finish")[1]
        self.assertIn("Final message: copy this template. Nothing else: no paragraphs, no other file names.", finish)
        template = finish.split("```\n")[1]
        self.assertEqual(template.splitlines(), [
            "N new items · X may affect your projects → see your to-do list (DATE-projects.md)",
            "🔴 [ID] what — fix",
            "Reports: briefings/DATE-news.md · briefings/DATE-projects.md",
        ])
        self.assertIn("Up to 3 marker lines, highest first.", finish)
        self.assertIn("Scan: the Result line replaces line 1", finish)
        self.assertIn('Scorecard off: "N new items".', finish)
        self.assertNotIn("a count line (briefing:", run)


if __name__ == "__main__":
    unittest.main()
