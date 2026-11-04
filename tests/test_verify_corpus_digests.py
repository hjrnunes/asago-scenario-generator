"""The replay corpus manifest's persisted digests recompute with the shared core.

The corpus stays outside every repository, so this test skips unless
``ASAGO_REPLAY_CORPUS`` names it; the gate sets that variable for the replay
checks only.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = os.environ.get("ASAGO_REPLAY_CORPUS")


def _verify_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "verify_corpus_digests_under_test",
        ROOT / "scripts" / "verify_corpus_digests.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclass resolves its string annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(
    not CORPUS,
    reason="set ASAGO_REPLAY_CORPUS to check the recording corpus",
)
def test_every_persisted_digest_recomputes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus = Path(CORPUS or "")
    assert (corpus / "MANIFEST.json").is_file()
    assert _verify_script().main(["--corpus", str(corpus)]) == 0
    report = capsys.readouterr().out
    assert " 0 mismatched," in report
    assert "total: " in report
