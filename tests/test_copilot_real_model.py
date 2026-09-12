"""
Unit tests for Copilot Real Model Configuration & Multi-Provider Chat Engine.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
from src.api.triage import (
    PROVIDER_SPECS,
    _mask_key,
    get_copilot_config,
    update_copilot_config,
    test_copilot_connection,
    copilot_chat,
)


class TestCopilotRealModel(unittest.TestCase):
    """Verify real model provider management, masking, and chat routing."""

    def test_provider_specs_complete(self):
        """Verify standard providers (Groq, Gemini, OpenAI, Ollama) are configured."""
        self.assertIn("groq", PROVIDER_SPECS)
        self.assertIn("gemini", PROVIDER_SPECS)
        self.assertIn("openai", PROVIDER_SPECS)
        self.assertIn("ollama", PROVIDER_SPECS)

        # Check Groq defaults
        groq = PROVIDER_SPECS["groq"]
        self.assertEqual(groq["default_model"], "qwen/qwen3.8-27b")
        model_ids = [m["id"] for m in groq["models"]]
        self.assertIn("qwen/qwen3.8-27b", model_ids)
        self.assertIn("llama-3.1-8b-instant", model_ids)

        # Check Gemini defaults
        gemini = PROVIDER_SPECS["gemini"]
        self.assertEqual(gemini["default_model"], "gemini-2.0-flash")

    def test_key_masking(self):
        """Verify API keys are safely masked in configuration responses."""
        self.assertEqual(_mask_key(""), "")
        self.assertEqual(_mask_key(None), "")
        self.assertEqual(_mask_key("short"), "••••••••")
        masked = _mask_key("gsk_abc123456789xyz")
        self.assertTrue(masked.startswith("gsk_"))
        self.assertTrue(masked.endswith("9xyz"))
        self.assertIn("••••••••", masked)

    def test_config_get_and_update(self):
        """Verify get and update copilot config works without environment corruption."""
        orig_config = get_copilot_config()
        self.assertIn("provider", orig_config)
        self.assertIn("providers", orig_config)

        # Update to gemini
        updated = update_copilot_config(
            provider="gemini",
            model="gemini-2.0-flash",
            api_key="test_dummy_key_12345",
            persist_to_env=False,
        )
        self.assertEqual(updated["provider"], "gemini")
        self.assertEqual(updated["model"], "gemini-2.0-flash")
        self.assertTrue(updated["has_key"])
        self.assertIn("••••••••", updated["masked_key"])

        # Restore original provider
        update_copilot_config(
            provider=orig_config["provider"],
            model=orig_config["model"],
            persist_to_env=False,
        )

    def test_test_copilot_connection_unknown_provider(self):
        """Verify unknown provider is rejected."""
        res = test_copilot_connection("non_existent_provider")
        self.assertEqual(res["status"], "error")
        self.assertIn("Unknown provider", res["message"])

    def test_offline_slm_chat_fallback(self):
        """Verify offline SLM answers when no real model key is active."""
        orig_config = get_copilot_config()
        # Temporarily clear key in memory and env for this test
        from src.api.triage import _COPILOT_STATE
        import os
        saved_state_key = _COPILOT_STATE.get("groq_api_key", "")
        saved_env_key = os.environ.get("GROQ_API_KEY")
        _COPILOT_STATE["groq_api_key"] = ""
        os.environ.pop("GROQ_API_KEY", None)

        try:
            res = copilot_chat("what is the weather today?")
            self.assertEqual(res["status"], "success")
            self.assertIn("Connect Real Model", res["answer"])
            self.assertFalse(res.get("has_real_model", True))

            # Keyword pattern query (filter)
            res_filter = copilot_chat("generate tcpdump filter for this flow")
            self.assertEqual(res_filter["status"], "success")
            self.assertIn("tcpdump", res_filter["answer"])
        finally:
            _COPILOT_STATE["groq_api_key"] = saved_state_key
            if saved_env_key:
                os.environ["GROQ_API_KEY"] = saved_env_key

    @patch("urllib.request.urlopen")
    def test_real_model_live_chat(self, mock_urlopen):
        """Verify live chat calls real model when credentials are provided."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"choices":[{"message":{"content":"Live LLaMA Response"}}]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        # Configure with key
        update_copilot_config(
            provider="groq",
            api_key="gsk_valid_mock_key_for_test",
            model="qwen/qwen3.8-27b",
            persist_to_env=False,
        )

        res = copilot_chat("can you explain quantum computing?")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["answer"], "Live LLaMA Response")
        self.assertTrue(res["has_real_model"])
        self.assertIn("Groq", res["model"])


if __name__ == "__main__":
    unittest.main()
