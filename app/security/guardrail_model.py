"""Hybrid prompt-injection classification and aggregate threat scoring."""
import threading
from dataclasses import dataclass
from typing import Iterable, List, Optional

from config import settings


class GuardrailModelError(RuntimeError):
    """Raised when the configured classifier cannot be loaded or evaluated."""


@dataclass(frozen=True)
class ModelPrediction:
    injection_probability: float
    intercepted_content: str


def _sample_indices(item_count: int, limit: int) -> List[int]:
    """Sample chunks across an entire document, including its first and last."""
    if item_count <= 0 or limit <= 0:
        return []
    if item_count <= limit:
        return list(range(item_count))
    if limit == 1:
        return [0]
    return sorted({round(index * (item_count - 1) / (limit - 1)) for index in range(limit)})


class PromptInjectionClassifier:
    """Lazily loaded Hugging Face prompt-injection classifier."""

    def __init__(self) -> None:
        self._tokenizer = None
        self._model = None
        self._injection_label_id: Optional[int] = None
        # Loading and inference are serialized to avoid duplicate model loads and
        # excessive CPU/RAM use when several API requests arrive simultaneously.
        self._lock = threading.Lock()

    def _load(self) -> None:
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(
                settings.guardrail_model_name,
                revision=settings.guardrail_model_revision,
            )
            model = AutoModelForSequenceClassification.from_pretrained(
                settings.guardrail_model_name,
                revision=settings.guardrail_model_revision,
                use_safetensors=True,
            )
            model.eval()

            labels = {
                str(label).upper(): int(label_id)
                for label_id, label in model.config.id2label.items()
            }
            injection_label_id = labels.get("INJECTION")
            if injection_label_id is None:
                raise GuardrailModelError(
                    "The guardrail model does not define an INJECTION output label"
                )

            self._tokenizer = tokenizer
            self._model = model
            self._injection_label_id = injection_label_id
        except GuardrailModelError:
            raise
        except Exception as exc:
            raise GuardrailModelError(
                "The pretrained guardrail model could not be loaded"
            ) from exc

    def predict(self, text: str) -> ModelPrediction:
        if not text.strip():
            return ModelPrediction(0.0, "")

        with self._lock:
            if self._model is None:
                self._load()

            try:
                import torch

                encoded = self._tokenizer(
                    text,
                    add_special_tokens=True,
                    truncation=True,
                    max_length=512,
                    stride=64,
                    return_overflowing_tokens=True,
                )
                input_ids = encoded["input_ids"]
                selected = _sample_indices(
                    len(input_ids),
                    max(1, settings.guardrail_model_max_chunks),
                )
                features = []
                for index in selected:
                    feature = {
                        name: encoded[name][index]
                        for name in self._tokenizer.model_input_names
                        if name in encoded
                    }
                    features.append(feature)

                batch = self._tokenizer.pad(features, padding=True, return_tensors="pt")
                with torch.inference_mode():
                    probabilities = torch.softmax(self._model(**batch).logits, dim=-1)

                injection_probabilities = probabilities[:, self._injection_label_id]
                highest = int(torch.argmax(injection_probabilities).item())
                probability = float(injection_probabilities[highest].item())
                excerpt = self._tokenizer.decode(
                    features[highest]["input_ids"],
                    skip_special_tokens=True,
                )[:300]
                return ModelPrediction(round(probability, 4), excerpt)
            except Exception as exc:
                raise GuardrailModelError(
                    "The pretrained guardrail model could not classify the page"
                ) from exc


_classifier = PromptInjectionClassifier()


def predict_prompt_injection(text: str) -> Optional[ModelPrediction]:
    """Classify text, or return None when ML classification is disabled."""
    if not settings.guardrail_model_enabled:
        return None
    return _classifier.predict(text)


def threat_score(
    hidden_findings: Iterable[dict],
    heuristic_findings: Iterable[dict],
    unicode_count: int,
    model_probability: Optional[float] = None,
) -> float:
    """Combine independent structural, deterministic, and ML signals."""
    hidden = list(hidden_findings)
    heuristic = list(heuristic_findings)
    probabilities = [min(0.8, float(item.get("weight", 0.0))) for item in heuristic]
    if hidden:
        probabilities.append(min(0.45, 0.12 + 0.04 * len(hidden)))
    if unicode_count:
        probabilities.append(min(0.35, 0.12 + 0.02 * unicode_count))
    if model_probability is not None:
        probabilities.append(min(0.95, max(0.0, model_probability)))

    remaining = 1.0
    for probability in probabilities:
        remaining *= 1.0 - probability
    return round(1.0 - remaining, 3)
