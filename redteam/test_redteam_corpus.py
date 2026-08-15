from __future__ import annotations

import unittest

import validate_artifacts


class RedTeamCorpusTests(unittest.TestCase):
    def test_corpus_is_complete_and_machine_readable(self):
        result = validate_artifacts.validate()
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["vectors"], 41)
        self.assertGreaterEqual(result["critical_attacks"], 15)


if __name__ == "__main__":
    unittest.main()
