"""US-101: Anthropic-first LLM config with current-generation model registry."""

import importlib

import pytest

import api.llm_config as llm_config_module


@pytest.fixture
def clean_env(monkeypatch):
    """Strip all LLM_* / ANTHROPIC_* env vars so defaults are exercised."""
    for var in (
        "LLM_PROVIDER",
        "LLM_MODEL",
        "LLM_DEEP_MODEL",
        "LLM_FAST_MODEL",
        "LLM_API_KEY",
        "ANTHROPIC_API_KEY",
        "LLM_API_BASE",
    ):
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


def make_config():
    importlib.reload(llm_config_module)
    return llm_config_module.LLMConfig()


class TestDefaults:
    def test_default_provider_is_anthropic(self, clean_env):
        assert make_config().provider == "anthropic"

    def test_default_model_is_opus_4_8(self, clean_env):
        assert make_config().model == "claude-opus-4-8"

    def test_deep_model_is_fable_5(self, clean_env):
        assert make_config().deep_model == "claude-fable-5"

    def test_fast_model_is_haiku_4_5(self, clean_env):
        assert make_config().fast_model == "claude-haiku-4-5"

    def test_no_gpt4_default_anywhere(self, clean_env):
        config = make_config()
        for value in (config.model, config.deep_model, config.fast_model):
            assert "gpt-4" not in value
            assert "claude-3-" not in value

    def test_default_endpoint_is_anthropic_messages(self, clean_env):
        assert (
            make_config().get_endpoint_url() == "https://api.anthropic.com/v1/messages"
        )


class TestEnvOverrides:
    def test_model_env_override(self, clean_env):
        clean_env.setenv("LLM_MODEL", "claude-haiku-4-5")
        assert make_config().model == "claude-haiku-4-5"

    def test_deep_model_env_override(self, clean_env):
        clean_env.setenv("LLM_DEEP_MODEL", "claude-opus-4-8")
        assert make_config().deep_model == "claude-opus-4-8"

    def test_fast_model_env_override(self, clean_env):
        clean_env.setenv("LLM_FAST_MODEL", "claude-sonnet-4-6")
        assert make_config().fast_model == "claude-sonnet-4-6"

    def test_provider_env_override_preserved(self, clean_env):
        clean_env.setenv("LLM_PROVIDER", "openai")
        assert make_config().provider == "openai"


class TestApiKeyResolution:
    def test_llm_api_key_wins(self, clean_env):
        clean_env.setenv("LLM_API_KEY", "k-explicit")
        clean_env.setenv("ANTHROPIC_API_KEY", "k-anthropic")
        assert make_config().api_key == "k-explicit"

    def test_anthropic_api_key_fallback(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "k-anthropic")
        config = make_config()
        assert config.api_key == "k-anthropic"
        assert config.is_configured()

    def test_anthropic_key_not_used_for_other_providers(self, clean_env):
        clean_env.setenv("LLM_PROVIDER", "openai")
        clean_env.setenv("ANTHROPIC_API_KEY", "k-anthropic")
        assert make_config().api_key is None

    def test_unconfigured_without_any_key(self, clean_env):
        assert not make_config().is_configured()


class TestHeaders:
    def test_anthropic_headers(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "k-anthropic")
        headers = make_config().get_headers()
        assert headers["x-api-key"] == "k-anthropic"
        assert headers["anthropic-version"] == "2023-06-01"
