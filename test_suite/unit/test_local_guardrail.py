"""Default checkpoint and offline loading checks; no downloads or real weights."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.security.guardrail_model import GuardrailModelError, PromptInjectionClassifier
from config import settings

ROOT = Path(__file__).resolve().parents[2]


def test_default_checkpoint_and_threshold_are_independent_of_cwd(monkeypatch, tmp_path):
    monkeypatch.delenv("SAFEPARSE_GUARDRAIL_MODEL_NAME", raising=False)
    monkeypatch.delenv("SAFEPARSE_GUARDRAIL_MODEL_FLAG_THRESHOLD", raising=False)
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location("local_model_config", ROOT / "config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.settings.guardrail_model_name == str(ROOT / "models/safeparse-ipi-v1")
    assert module.settings.guardrail_model_flag_threshold == .5029


def fake_transformers(monkeypatch, labels):
    tokenizer = SimpleNamespace(from_pretrained=Mock(return_value=object()))
    model = SimpleNamespace(config=SimpleNamespace(id2label=labels), eval=Mock())
    factory = SimpleNamespace(from_pretrained=Mock(return_value=model))
    monkeypatch.setitem(sys.modules, "transformers", SimpleNamespace(
        AutoTokenizer=tokenizer, AutoModelForSequenceClassification=factory))
    return tokenizer, factory, model


def test_missing_checkpoint_never_falls_back_to_hub(monkeypatch, tmp_path):
    tokenizer, factory, _ = fake_transformers(monkeypatch, {0: "BENIGN", 1: "INJECTION"})
    monkeypatch.setattr(settings, "guardrail_model_name", str(tmp_path / "missing"))
    with pytest.raises(GuardrailModelError, match="directory is missing"):
        PromptInjectionClassifier()._load()
    tokenizer.from_pretrained.assert_not_called()
    factory.from_pretrained.assert_not_called()


def test_checkpoint_loaded_offline_with_correct_injection_label(monkeypatch, tmp_path):
    tokenizer, factory, model = fake_transformers(monkeypatch, {0: "BENIGN", 1: "INJECTION"})
    monkeypatch.setattr(settings, "guardrail_model_name", str(tmp_path))
    classifier = PromptInjectionClassifier()
    classifier._load()
    tokenizer.from_pretrained.assert_called_once_with(str(tmp_path), local_files_only=True, trust_remote_code=False)
    factory.from_pretrained.assert_called_once_with(str(tmp_path), local_files_only=True,
                                                   trust_remote_code=False, use_safetensors=True)
    model.eval.assert_called_once()
    assert classifier._injection_label_id == 1


def test_incompatible_checkpoint_is_rejected(monkeypatch, tmp_path):
    fake_transformers(monkeypatch, {0: "LABEL_0", 1: "LABEL_1"})
    monkeypatch.setattr(settings, "guardrail_model_name", str(tmp_path))
    with pytest.raises(GuardrailModelError, match="INJECTION output label"):
        PromptInjectionClassifier()._load()
