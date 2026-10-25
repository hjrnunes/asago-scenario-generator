"""The offline script that runs the mechanism-candidate join over saved files."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    MechanismCandidate,
)

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "graph_join_candidates.py"


def _script() -> ModuleType:
    name = "graph_join_candidates_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _structure(source_kind: str) -> dict:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Answer",
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "Belief"},
                ],
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Reply",
                        "target": {"type": "controlled_process", "id": "CP-1"},
                        "effect_kind": "model_output",
                        "process_model_refs": ["PM-1-1"],
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Signal",
                        "updates": "PM-1-1",
                        "source": {"type": "controlled_process", "id": "CP-1"},
                        "source_kind": source_kind,
                    }
                ],
            }
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Chat"}],
    }


def _write(path: Path, source_kind: str = "user_message") -> Path:
    path.write_text(yaml.safe_dump(_structure(source_kind)))
    return path


def test_load_reports_missing_and_invalid_files_as_unloadable(tmp_path: Path) -> None:
    good = _write(tmp_path / "good.yaml")
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("responsibilities: []\n")

    units = _script().load_units(
        [("good", good), ("missing", tmp_path / "absent.yaml"), ("bad", invalid)]
    )

    assert [unit.structure is not None for unit in units] == [True, False, False]
    assert units[0].candidates == (
        MechanismCandidate("user_claim", ("FB-1-1", "PM-1-1", "CA-1-1")),
    )
    assert units[1].digest is None
    assert units[1].error.startswith("FileNotFoundError")
    assert units[2].digest is not None
    assert units[2].error.startswith("ValidationError")


def test_duplicates_name_the_first_unit_with_the_same_bytes(tmp_path: Path) -> None:
    first = _write(tmp_path / "a.yaml")
    copy = tmp_path / "b.yaml"
    copy.write_bytes(first.read_bytes())
    other = _write(tmp_path / "c.yaml", "retrieved_content")
    script = _script()

    units = script.load_units(
        [("a", first), ("c", other), ("b", copy), ("a-again", first)]
    )
    rows = [script._unit_counts(unit, units) for unit in units]

    assert [unit.duplicate_of for unit in units] == [None, None, 0, 0]
    assert [row["duplicate_of"] for row in rows] == [None, None, "a", "a"]
    assert [row["index"] for row in rows] == [0, 1, 2, 3]


@pytest.mark.parametrize(
    ("labels", "message"),
    [(["a", " "], "blank label"), (["a", "a"], "repeats unit 0")],
)
def test_blank_or_repeated_labels_stop_before_loading(
    tmp_path: Path, labels: list[str], message: str
) -> None:
    path = _write(tmp_path / "a.yaml")

    with pytest.raises(SystemExit, match=message):
        _script().load_units([(label, path) for label in labels])


def test_aggregate_reports_spread_and_small_unit_share() -> None:
    rows = [
        {"candidates": count, "paths": count, "by_mechanism": {"user_claim": count}}
        for count in (0, 3, 5, 8)
    ]

    aggregate = _script()._aggregate(rows)

    assert aggregate["units"] == 4
    assert aggregate["candidates"] == {
        "total": 16,
        "min": 0,
        "median": 4,
        "max": 8,
        "share_at_most_5": 0.75,
    }
    assert aggregate["by_mechanism"] == {"user_claim": 16}
    assert aggregate["units_with_no_candidate"] == 1


def _units(count: int, candidates_each: int) -> list:
    script = _script()
    return [
        script.Unit(
            index=index,
            label=f"u{index}",
            path=Path(f"u{index}.yaml"),
            candidates=tuple(
                MechanismCandidate("user_claim", (f"FB-{n}-1", f"PM-{n}-1", "CA-1-1"))
                for n in range(1, candidates_each + 1)
            ),
        )
        for index in range(count)
    ]


def test_sample_covers_every_structure_then_draws_the_rest() -> None:
    units = _units(4, 3)

    sample = _script()._sample(units, 6, seed=7)

    assert len(sample) == len({(unit.index, item) for unit, item, _ in sample}) == 6
    assert [unit.index for unit, _, draw in sample if draw == "one_per_structure"] == [
        0,
        1,
        2,
        3,
    ]
    assert [draw for _, _, draw in sample].count("uniform_remainder") == 2
    assert sample == _script()._sample(units, 6, seed=7)


def test_sample_chooses_structures_by_seed_when_more_than_it_holds() -> None:
    units = _units(40, 1)

    sample = _script()._sample(units, 30, seed=7)
    indexes = [unit.index for unit, _, _ in sample]

    assert len(set(indexes)) == 30
    assert indexes != list(range(30))
    assert indexes == [unit.index for unit, _, _ in _script()._sample(units, 30, 7)]
    assert indexes != [unit.index for unit, _, _ in _script()._sample(units, 30, 8)]


def test_link_record_names_the_link_target_as_receiver(tmp_path: Path) -> None:
    data = _structure("retrieved_content")
    data["responsibilities"].append({"resp_id": "RESP-2", "description": "Review"})
    data["coordination_links"] = [
        {
            "link_id": "CL-1",
            "source": "RESP-1",
            "target": "RESP-2",
            "shared_pm": "PM-1-1",
            "coordination_mechanism": {
                "cm_id": "CM-1",
                "description": "Share belief",
                "payload": "belief",
            },
            "description": "Controller 1 shares its belief.",
        }
    ]
    path = tmp_path / "linked.yaml"
    path.write_text(yaml.safe_dump(data))
    script = _script()
    (unit,) = script.load_units([("linked", path)])

    rows = [
        script._judging_record(unit, item)
        for item in unit.candidates
        if item.path[2] == "CL-1"
    ]

    assert {row["mechanism"] for row in rows} == {
        "retrieved_instructions",
        "delegated_authority",
    }
    for row in rows:
        link = row["coordination_link"]
        assert link["source"]["resp_id"] == "RESP-1"
        assert link["receiving_controller"]["resp_id"] == "RESP-2"
        assert row["control_action"] is None


def _authority_structure() -> dict:
    """User-message channels (assessed, absent, authoritative) and an own check."""
    data = _structure("user_message")
    first = data["responsibilities"][0]
    first["process_model_parts"] += [
        {"pm_id": "PM-1-2", "description": "Claim"},
        {"pm_id": "PM-1-3", "description": "Own check"},
    ]
    first["control_actions"][0]["process_model_refs"] += ["PM-1-2", "PM-1-3"]
    channel = first["feedback_channels"][0]
    channel["authority_for_update"] = {
        "status": "non_authoritative",
        "basis": "The user may not set it.",
    }
    first["feedback_channels"] += [
        {**channel, "fb_id": "FB-1-2", "updates": "PM-1-2"},
        {
            **channel,
            "fb_id": "FB-1-3",
            "updates": "PM-1-3",
            "source": {"type": "responsibility", "id": "RESP-1"},
            "source_kind": "conversation_history",
        },
    ]
    del first["feedback_channels"][1]["authority_for_update"]
    first["feedback_channels"].append(
        {
            **channel,
            "fb_id": "FB-1-4",
            "updates": "PM-1-1",
            "authority_for_update": {"status": "authoritative", "basis": "Backend."},
        }
    )
    return data


def test_authority_filter_counts_kept_and_dropped(tmp_path: Path) -> None:
    path = tmp_path / "authority.yaml"
    path.write_text(yaml.safe_dump(_authority_structure()))
    script = _script()

    (plain,) = script.load_units([("u", path)])
    (unit,) = script.load_units([("u", path)], authority_filter=True)
    plain_row = script._unit_counts(plain, [plain])
    row = script._unit_counts(unit, [unit])

    assert plain.join is None and "unfiltered_candidates" not in plain_row
    assert [item.path[0] for item in unit.candidates] == ["FB-1-1", "FB-1-2"]
    assert unit.unfiltered == plain.candidates
    assert row["candidates"] == 2 and row["unfiltered_candidates"] == 4
    assert (row["kept_assessed"], row["kept_unknown"]) == (1, 1)
    assert row["kept_unknown_missing"] == 1
    assert row["dropped_by_reason"] == {"authoritative": 1, "own_controller": 1}
    assert row["channel_authority"] == {
        "authoritative": 1,
        "non_authoritative": 2,
        "conditional": 0,
        "unknown": 0,
        "missing": 1,
    }
    assert row["joined_channels"] == 3
    record = script._judging_record(unit, unit.candidates[1])
    assert record["authority_status"] == "unknown"
    assert record["authority_recorded"] is False
    assert record["reach_basis"] == "source_kind"
    assert "authority_status" not in script._judging_record(plain, plain.candidates[0])
