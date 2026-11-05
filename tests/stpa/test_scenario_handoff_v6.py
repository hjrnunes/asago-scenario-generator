"""scenario-handoff-v6 renames one wire field and changes nothing a model sees.

v6 writes ``attack_shape.indirect.party_relation.controlling_party`` where v5
writes ``controller``, carries the contract envelope its spec requires, and
signs with its own digest domain. The model keeps the v5 attribute, and the
Stage 5 shape-step reply never mentions the resolved party relation, so every
prompt and every structured-output schema stays byte-identical. Every test is
offline.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_contracts_core import (
    ENVELOPE_FIELD,
    installed_specs,
    read_handoff,
    schema_violations,
)
from asago_scenario_generator.request_schema import portable_request_schema
from asago_scenario_generator.stpa.models.attack_shape import ItemController
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_DIGEST_DOMAIN_V5,
    HANDOFF_DIGEST_DOMAIN_V6,
    HANDOFF_DIGEST_DOMAINS,
    HANDOFF_SCHEMA_VERSION_V5,
    HANDOFF_SCHEMA_VERSION_V6,
    HANDOFF_SCHEMA_VERSIONS,
    HANDOFF_WRITER,
    ScenarioHandoffV5,
    ScenarioHandoffV6,
    handoff_document,
    handoff_model,
    handoff_payload_digest,
    handoff_schema_violations,
    verify_handoff_digest,
    write_scenario_handoff,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_schema import handoff_schema
from asago_scenario_generator.stpa.scenario_prod.handoff_v5 import (
    build_scenario_handoff_v5,
    build_scenario_handoff_v6,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeStepConfig,
    response_model_for,
)
from tests.stpa.test_narration import adversarial
from tests.stpa.test_scenario_handoff_v5 import _envelope

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "data/contracts/scenario-handoff"
KIT = CONTRACT_ROOT / HANDOFF_SCHEMA_VERSION_V6
CASES = KIT / "cases"


def _built() -> ScenarioHandoffV6:
    return build_scenario_handoff_v6(_envelope(adversarial()))


def _case(relative: str) -> dict:
    return json.loads((CASES / relative).read_text(encoding="utf-8"))


def _relation(document: dict) -> dict:
    return document["attack_shape"]["indirect"]["party_relation"]


def test_the_v6_document_writes_controlling_party() -> None:
    handoff = _built()
    document = handoff_document(handoff)

    assert handoff.schema_version == HANDOFF_SCHEMA_VERSION_V6
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V6
    assert set(_relation(document)) == {"controlling_party", "benign_user_actor_ref"}
    assert _relation(document)["controlling_party"] == ItemController.THIRD_PARTY.value
    # The model keeps the v5 attribute; only the document renames it.
    assert (
        handoff.attack_shape.indirect.party_relation.controller
        is ItemController.THIRD_PARTY
    )


def test_the_v5_document_keeps_the_model_facing_name() -> None:
    handoff = build_scenario_handoff_v5(_envelope(adversarial()))
    document = handoff.model_dump(mode="json", exclude_none=True)

    assert set(_relation(document)) == {"controller", "benign_user_actor_ref"}
    assert _relation(document)["controller"] == ItemController.THIRD_PARTY.value


def test_the_v6_model_reads_both_the_wire_and_the_model_name() -> None:
    payload = _built().model_dump(mode="json", exclude_none=True, by_alias=True)

    renamed = copy.deepcopy(payload)
    relation = _relation(renamed)
    relation["controller"] = relation.pop("controlling_party")

    for document in (payload, renamed):
        handoff = ScenarioHandoffV6.model_validate(document)
        assert handoff.attack_shape.indirect.party_relation.controller is (
            ItemController.THIRD_PARTY
        )


def test_each_model_refuses_the_other_version() -> None:
    v6_payload = _built().model_dump(mode="json", exclude_none=True, by_alias=True)
    v5_payload = (
        build_scenario_handoff_v5(_envelope(adversarial()))
        .model_dump(mode="json", exclude_none=True)
        .copy()
    )

    with pytest.raises(ValidationError):
        ScenarioHandoffV5.model_validate(v6_payload)
    with pytest.raises(ValidationError):
        ScenarioHandoffV6.model_validate(v5_payload)


def test_the_published_versions_and_digest_domains_are_listed() -> None:
    assert HANDOFF_SCHEMA_VERSIONS == (
        HANDOFF_SCHEMA_VERSION_V5,
        HANDOFF_SCHEMA_VERSION_V6,
    )
    assert set(HANDOFF_DIGEST_DOMAINS) == set(HANDOFF_SCHEMA_VERSIONS)
    assert HANDOFF_DIGEST_DOMAINS[HANDOFF_SCHEMA_VERSION_V6] == HANDOFF_DIGEST_DOMAIN_V6
    assert HANDOFF_DIGEST_DOMAIN_V6 != HANDOFF_DIGEST_DOMAIN_V5
    assert handoff_model(HANDOFF_SCHEMA_VERSION_V6) is ScenarioHandoffV6
    assert handoff_model(HANDOFF_SCHEMA_VERSION_V5) is ScenarioHandoffV5
    with pytest.raises(ValueError, match="unsupported scenario handoff schema_version"):
        handoff_model("scenario-handoff-v9")


def test_the_v6_digest_signs_the_aliased_document() -> None:
    handoff = _built()
    payload = handoff.model_dump(mode="json", exclude_none=True, by_alias=True)
    payload.pop("content_digest")

    verify_handoff_digest(handoff)
    assert handoff_payload_digest(payload) == handoff.content_digest

    # The same content relabelled v5 is not a v5 document: v5 names the field
    # `controller` and signs with its own domain, so the digest differs.
    relabelled = {**payload, "schema_version": HANDOFF_SCHEMA_VERSION_V5}
    assert handoff_payload_digest(relabelled) != handoff.content_digest

    tampered = handoff.model_copy(update={"content_digest": "sha256:" + "0" * 64})
    with pytest.raises(ValueError, match="content_digest does not match"):
        verify_handoff_digest(tampered)
    with pytest.raises(ValueError, match="unsupported scenario handoff schema_version"):
        handoff_payload_digest({**payload, "schema_version": "scenario-handoff-v9"})


def test_the_v6_writer_stamps_the_envelope_the_spec_requires(
    tmp_path: Path,
) -> None:
    handoff = _built()
    spec = installed_specs().spec("scenario-handoff", HANDOFF_SCHEMA_VERSION_V6)

    handoff_path, feature_path = write_scenario_handoff(handoff, tmp_path)
    document = yaml.safe_load(handoff_path.read_text(encoding="utf-8"))
    envelope = document[ENVELOPE_FIELD]

    assert (envelope["id"], envelope["version"]) == (
        "scenario-handoff",
        HANDOFF_SCHEMA_VERSION_V6,
    )
    assert envelope["spec_digest"] == spec.spec_digest
    assert envelope["requires"] == []
    assert envelope["provenance"]["writer"] == HANDOFF_WRITER
    assert envelope["provenance"]["validator_version"].startswith(
        "asago-contracts-core "
    )
    assert _relation(document)["controlling_party"] == ItemController.THIRD_PARTY.value
    assert read_handoff(document).version == HANDOFF_SCHEMA_VERSION_V6
    assert feature_path.read_text(encoding="utf-8") == handoff.gherkin.to_feature_text()


def test_the_reader_accepts_both_versions(tmp_path: Path) -> None:
    v5_path, _ = write_scenario_handoff(
        build_scenario_handoff_v5(_envelope(adversarial())), tmp_path / "v5"
    )
    v6_path, _ = write_scenario_handoff(_built(), tmp_path / "v6")

    v5 = yaml.safe_load(v5_path.read_text(encoding="utf-8"))
    v6 = yaml.safe_load(v6_path.read_text(encoding="utf-8"))

    assert read_handoff(v5).version == HANDOFF_SCHEMA_VERSION_V5
    assert read_handoff(v6).version == HANDOFF_SCHEMA_VERSION_V6


def test_the_v5_writer_keeps_the_recorded_bare_document(tmp_path: Path) -> None:
    handoff = build_scenario_handoff_v5(_envelope(adversarial()))

    handoff_path, _ = write_scenario_handoff(handoff, tmp_path)
    document = yaml.safe_load(handoff_path.read_text(encoding="utf-8"))

    assert ENVELOPE_FIELD not in document
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V5
    assert set(_relation(document)) == {"controller", "benign_user_actor_ref"}
    assert read_handoff(document).version == HANDOFF_SCHEMA_VERSION_V5


def test_the_v6_schema_publishes_the_wire_name() -> None:
    schema = handoff_schema(HANDOFF_SCHEMA_VERSION_V6)

    assert schema["properties"]["schema_version"]["const"] == (
        HANDOFF_SCHEMA_VERSION_V6
    )
    assert set(schema["$defs"]["PartyRelation"]["properties"]) == {
        "controlling_party",
        "benign_user_actor_ref",
    }
    assert set(handoff_schema()["$defs"]["PartyRelation"]["properties"]) == {
        "controller",
        "benign_user_actor_ref",
    }


@pytest.mark.parametrize(
    "case", sorted((CASES / "valid").glob("*.json")), ids=lambda path: path.stem
)
def test_every_v6_valid_case_holds(case: Path) -> None:
    assert handoff_schema_violations(json.loads(case.read_text(encoding="utf-8"))) == []


@pytest.mark.parametrize(
    ("name", "codes"),
    [
        ("v5-worst-case-threat-blank.json", ["schema_violation:worst_case_threat"]),
        ("v5-procedure-channel-not-enumerated.json", ["schema_violation:procedure"]),
        ("v5-causal-factor-belief-missing.json", ["schema_violation:causal_factors"]),
    ],
)
def test_a_v6_invalid_case_reports_its_codes(name: str, codes: list[str]) -> None:
    assert handoff_schema_violations(_case(f"invalid/{name}")) == codes


def test_the_v6_kit_records_the_same_codes_as_v5() -> None:
    v6 = json.loads((CASES / "expected-violations.json").read_text(encoding="utf-8"))
    v5 = json.loads(
        (
            CONTRACT_ROOT / HANDOFF_SCHEMA_VERSION_V5 / "cases/expected-violations.json"
        ).read_text(encoding="utf-8")
    )

    assert v6 == v5


def test_the_v6_schema_refuses_controller_though_the_model_reads_it() -> None:
    payload = _case("valid/adversarial-indirect-listing.json")
    relation = _relation(payload)
    relation["controller"] = relation.pop("controlling_party")

    # The model accepts both names, so a migrating producer reads either
    # document; the published v6 schema is closed, so a reader refuses the old
    # name.
    assert ScenarioHandoffV6.model_validate(payload).schema_version == (
        HANDOFF_SCHEMA_VERSION_V6
    )
    assert [violation.code for violation in schema_violations(payload)] == [
        "schema_violation:attack_shape"
    ]


def test_the_v5_schema_refuses_controlling_party() -> None:
    payload = build_scenario_handoff_v5(_envelope(adversarial())).model_dump(
        mode="json", exclude_none=True
    )
    relation = _relation(payload)
    relation["controlling_party"] = relation.pop("controller")

    assert ScenarioHandoffV5.model_validate(payload).schema_version == (
        HANDOFF_SCHEMA_VERSION_V5
    )
    assert [violation.code for violation in schema_violations(payload)] == [
        "schema_violation:attack_shape"
    ]


def test_the_v5_contract_schema_is_the_one_v5_documents_validate_against() -> None:
    published = json.loads(
        (CONTRACT_ROOT / HANDOFF_SCHEMA_VERSION_V5 / "schema.json").read_text(
            encoding="utf-8"
        )
    )
    default = ScenarioHandoffV5.model_json_schema()

    # ``handoff_schema`` publishes the v5 field names, and its default version is
    # v5. The model's default schema publishes the v6 serialization alias instead,
    # so no caller may validate a v5 document against it.
    assert handoff_schema(HANDOFF_SCHEMA_VERSION_V5) == published
    assert handoff_schema() == published
    assert default != published
    assert "controlling_party" in default["$defs"]["PartyRelation"]["properties"]
    assert set(published["$defs"]["PartyRelation"]["properties"]) == {
        "controller",
        "benign_user_actor_ref",
    }

    case = json.loads(
        (
            CONTRACT_ROOT
            / HANDOFF_SCHEMA_VERSION_V5
            / "cases/valid/adversarial-indirect-listing.json"
        ).read_text(encoding="utf-8")
    )
    assert list(Draft202012Validator(published).iter_errors(case)) == []
    assert list(Draft202012Validator(default).iter_errors(case)), (
        "the model's default schema must not accept the v5 controller field"
    )


def test_the_alias_never_reaches_the_stage_5_shape_step_schema() -> None:
    """The party relation is resolved after the reply, so its alias is not sent."""

    for forged in (False, True):
        model = response_model_for(ShapeStepConfig(allow_forged_transcript=forged))
        schema = portable_request_schema(model.model_json_schema())
        rendered = json.dumps(schema, sort_keys=True, separators=(",", ":"))
        assert "controlling_party" not in rendered
        assert "PartyRelation" not in rendered
