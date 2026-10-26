"""Small synthetic tensors only; no Hub downloads or corpus training."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location("safeparse_train_memory", Path(__file__).parents[2] / "training/train.py")
train = importlib.util.module_from_spec(spec)
spec.loader.exec_module(train)


def test_checkpointed_window_gradients_match_streamed_reference():
    torch = pytest.importorskip("torch")

    class Model(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = torch.nn.Embedding(16, 8)
            self.dropout = torch.nn.Dropout(.2)
            self.head = torch.nn.Linear(8, 2)
            self.batch_sizes = []

        def forward(self, input_ids):
            self.batch_sizes.append(input_ids.shape[0])
            x = self.dropout(self.embedding(input_ids).mean(dim=1))
            return SimpleNamespace(logits=self.head(x))

    model = Model()
    batch = {"input_ids": torch.tensor([[1, 2, 3], [4, 5, 6], [7, 8, 9]])}
    torch.manual_seed(17)
    margin = train.doc_margin(model, batch, "cpu", low_memory=True)
    margin.backward()
    gradients = [p.grad.clone() for p in model.parameters()]
    value = margin.detach()
    assert set(model.batch_sizes) == {1}
    model.zero_grad(set_to_none=True)
    torch.manual_seed(17)
    reference = torch.stack([train.doc_margin(model, {"input_ids": ids[None]}, "cpu")
                             for ids in batch["input_ids"]]).max()
    reference.backward()
    torch.testing.assert_close(value, reference.detach())
    for actual, parameter in zip(gradients, model.parameters()):
        torch.testing.assert_close(actual, parameter.grad)

    model.eval()
    model.batch_sizes.clear()
    with torch.inference_mode():
        streamed = train.doc_margin(model, batch, "cpu")
        expected_logits = model(**batch).logits
        expected = (expected_logits[:, 1] - expected_logits[:, 0]).max()
        torch.testing.assert_close(streamed, expected)
    assert model.batch_sizes[:-1] == [1, 1, 1]


def test_low_memory_flag():
    args = train.parse_args(["--output-dir", "fixture", "--low-memory", "--device", "mps"])
    assert args.low_memory
