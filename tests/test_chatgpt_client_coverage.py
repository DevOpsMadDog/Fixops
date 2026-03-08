"""Tests for ChatGPT client wrapper — UserMessage, get_primary_llm_api_key."""

from core.services.enterprise.chatgpt_client import (
    UserMessage,
    get_primary_llm_api_key,
)


class TestUserMessage:
    def test_create(self):
        msg = UserMessage(text="Hello world")
        assert msg.text == "Hello world"

    def test_empty_text(self):
        msg = UserMessage(text="")
        assert msg.text == ""

    def test_long_text(self):
        long = "x" * 10000
        msg = UserMessage(text=long)
        assert len(msg.text) == 10000


class TestGetPrimaryLLMApiKey:
    def test_returns_none_or_string(self):
        # In CI, no key is set
        result = get_primary_llm_api_key()
        assert result is None or isinstance(result, str)

    def test_returns_string_type(self):
        result = get_primary_llm_api_key()
        # Should return either None or a string
        assert result is None or isinstance(result, str)
