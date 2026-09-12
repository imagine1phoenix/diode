"""
Unit tests for Copilot Groq Model Integration & Chat Engine.
"""

from __future__ import annotations

import unittest
import urllib.error
from unittest.mock import MagicMock, patch
from src.api.triage import (
    _mask_key,
    _get_active_groq_key,
    get_copilot_config,
    update_copilot_config,
    test_copilot_connection,
    copilot_chat,
    GROQ_MODEL,
)


class TestCopilotGroqModel(unittest.TestCase):
    """Verify Groq LLM configuration, masking, dynamic keys, and chat routing."""

    def test_copilot_config_defaults(self):
        """Verify standard fixed Groq configuration is exposed."""
        cfg = get_copilot_config()
        self.assertEqual(cfg["status"], "success")
        self.assertEqual(cfg["provider"], "groq")
        self.assertEqual(cfg["model"], GROQ_MODEL)
        self.assertTrue(cfg["has_key"])
        self.assertIn("••••••••", cfg["masked_key"])

    def test_key_masking(self):
        """Verify API keys are safely masked in configuration responses."""
        self.assertEqual(_mask_key(""), "")
        self.assertEqual(_mask_key(None), "")
        self.assertEqual(_mask_key("short"), "••••••••")
        masked = _mask_key("mock_key_123456789xyz")
        self.assertTrue(masked.startswith("mock"))
        self.assertTrue(masked.endswith("9xyz"))
        self.assertIn("••••••••", masked)

    @patch("src.api.triage.config.PROJECT_ROOT")
    def test_config_update_key(self, mock_root):
        """Verify updating copilot config with a new key updates the active key."""
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_root.__truediv__.side_effect = lambda x: Path(tmpdir) / x
            test_key = "mock_test_key_override_1234567890abcdef"
            updated = update_copilot_config(api_key=test_key)
            self.assertEqual(updated["provider"], "groq")
            self.assertTrue(updated["has_key"])
            self.assertTrue(updated["masked_key"].startswith("mock"))
            self.assertTrue(updated["masked_key"].endswith("cdef"))

    @patch("urllib.request.urlopen")
    def test_real_model_live_chat(self, mock_urlopen):
        """Verify live chat calls real model when credentials are provided."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"choices":[{"message":{"content":"Live Groq LLaMA Response"}}]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = copilot_chat("what is the mitigation plan?")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["answer"], "Live Groq LLaMA Response")
        self.assertTrue(res["has_real_model"])
        self.assertIn("Groq", res["model"])

    @patch("urllib.request.urlopen")
    def test_groq_401_error_handling(self, mock_urlopen):
        """Verify 401 Unauthorized returns helpful diagnostic and falls back to offline SLM."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.groq.com",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )

        res = copilot_chat("generate tcpdump filter for this flow")
        self.assertEqual(res["status"], "error")
        self.assertIn("401", res["answer"])
        self.assertIn("Air-Gapped Offline SLM Backup Response", res["answer"])
        self.assertIn("tcpdump", res["answer"])


if __name__ == "__main__":
    unittest.main()
