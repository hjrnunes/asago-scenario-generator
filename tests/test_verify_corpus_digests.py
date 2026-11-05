"""The replay corpus manifest's persisted digests recompute with the shared core.

The corpus stays outside every repository, so this test skips unless
``ASAGO_REPLAY_CORPUS`` names it; the gate sets that variable for the replay
checks only. A variable that names no directory fails and names the path.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _replay_corpus() -> Path:
    """Return the replay corpus the manifest lives in.

    The corpus stays outside every repository, so an unset ``ASAGO_REPLAY_CORPUS``
    skips the test that needs it. VAL-SAFETY-006: a set variable that names no
    directory fails and names the path.
    """

    configured = os.environ.get("ASAGO_REPLAY_CORPUS")
    if not configured:
        pytest.skip("set ASAGO_REPLAY_CORPUS to check the recording corpus")
    corpus = Path(configured)
    if not corpus.is_dir():
        pytest.fail(f"the replay corpus directory does not exist: {corpus}")
    return corpus


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


def test_a_missing_replay_corpus_fails_and_names_the_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "no-such-corpus"
    monkeypatch.setenv("ASAGO_REPLAY_CORPUS", str(missing))

    with pytest.raises(pytest.fail.Exception) as raised:
        _replay_corpus()

    assert str(missing) in str(raised.value)


@pytest.mark.replay_corpus
def test_every_persisted_digest_recomputes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus = _replay_corpus()
    assert (corpus / "MANIFEST.json").is_file()
    assert _verify_script().main(["--corpus", str(corpus)]) == 0
    report = capsys.readouterr().out
    assert " 0 mismatched," in report
    assert "total: " in report
