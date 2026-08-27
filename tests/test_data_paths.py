from pathlib import Path

from asago_scenario_generator.data.paths import resolve_data_root


def test_resolve_data_root_prefers_installed_bundle(tmp_path: Path) -> None:
    package = tmp_path / "site-packages" / "asago_scenario_generator"
    bundled = package / "data" / "bundled"
    (bundled / "taxonomies").mkdir(parents=True)

    assert resolve_data_root(package) == bundled


def test_resolve_data_root_supports_source_checkout(tmp_path: Path) -> None:
    package = tmp_path / "project" / "src" / "asago_scenario_generator"
    source = tmp_path / "project" / "data"
    package.mkdir(parents=True)
    (source / "taxonomies").mkdir(parents=True)

    assert resolve_data_root(package) == source
