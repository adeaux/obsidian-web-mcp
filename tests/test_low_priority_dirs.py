"""VAULT_LOW_PRIORITY_DIRS: hits in those folders rank after everything else.

Nothing is hidden. vault_search spends its budget on the rest of the vault first
and fills what is left from the low-priority folders, marking those hits
low_priority. A search scoped inside one of them is a normal search.
"""

import json
import shutil

import pytest

from obsidian_vault_mcp import config
from obsidian_vault_mcp.tools import search as search_mod
from obsidian_vault_mcp.tools.search import vault_search


@pytest.fixture
def archive_vault(vault_dir, monkeypatch):
    archive = vault_dir / "3 Archive" / "Client"
    archive.mkdir(parents=True)
    for i in range(3):
        (archive / f"old-{i}.md").write_text(f"Archived note {i} about zucchini.\n")
    (vault_dir / "current.md").write_text("A current note about zucchini.\n")
    (vault_dir / "subfolder" / "also-current.md").write_text("Zucchini again, current.\n")
    monkeypatch.setattr(config, "VAULT_LOW_PRIORITY_DIRS", ["3 Archive"])
    return vault_dir


@pytest.fixture(params=["ripgrep", "python"])
def engine(request, monkeypatch):
    if request.param == "ripgrep":
        if not shutil.which("rg"):
            pytest.skip("ripgrep not installed")
    else:
        monkeypatch.setattr(search_mod.shutil, "which", lambda _name: None)
    return request.param


def _results(**kwargs):
    return json.loads(vault_search(**kwargs))["results"]


def test_archive_hits_come_last_and_are_marked(archive_vault, engine):
    results = _results(query="zucchini", max_results=20)
    paths = [r["path"] for r in results]
    flags = [r.get("low_priority", False) for r in results]

    assert sorted(paths[:2]) == ["current.md", "subfolder/also-current.md"]
    assert all(p.startswith("3 Archive/") for p in paths[2:]) and len(paths) == 5
    assert flags == [False, False, True, True, True]


def test_archive_only_fills_leftover_budget(archive_vault, engine):
    results = _results(query="zucchini", max_results=2)
    assert [r.get("low_priority", False) for r in results] == [False, False]
    assert not any(r["path"].startswith("3 Archive/") for r in results)


def test_archive_found_when_nothing_else_matches(archive_vault, engine):
    results = _results(query="Archived note 1")
    assert [r["path"] for r in results] == ["3 Archive/Client/old-1.md"]
    assert results[0]["low_priority"] is True


def test_search_scoped_inside_archive_is_normal(archive_vault, engine):
    results = _results(query="zucchini", path_prefix="3 Archive")
    assert len(results) == 3
    assert not any("low_priority" in r for r in results)


def test_filename_hits_follow_the_same_order(archive_vault, engine):
    (archive_vault / "3 Archive" / "Client" / "budget.md").write_text("x\n")
    (archive_vault / "budget.md").write_text("y\n")
    results = _results(query="budget")
    assert [r["path"] for r in results] == ["budget.md", "3 Archive/Client/budget.md"]
    assert results[1]["low_priority"] is True


def test_unset_means_unchanged(archive_vault, engine, monkeypatch):
    monkeypatch.setattr(config, "VAULT_LOW_PRIORITY_DIRS", [])
    results = _results(query="zucchini", max_results=20)
    assert len(results) == 5
    assert not any("low_priority" in r for r in results)


def test_missing_folder_is_ignored(archive_vault, engine, monkeypatch):
    monkeypatch.setattr(config, "VAULT_LOW_PRIORITY_DIRS", ["No Such Folder"])
    assert len(_results(query="zucchini")) == 5


def test_frontmatter_search_ranks_archive_last(archive_vault):
    from obsidian_vault_mcp.server import frontmatter_index
    from obsidian_vault_mcp.tools.search import vault_search_frontmatter

    (archive_vault / "3 Archive" / "Client" / "a.md").write_text("---\nstatus: active\n---\nold\n")
    frontmatter_index.rebuild()
    results = json.loads(vault_search_frontmatter(field="status", value="active"))["results"]
    paths = [r["path"] for r in results]
    assert paths[-1] == "3 Archive/Client/a.md"
    assert results[-1]["low_priority"] is True
    assert "low_priority" not in results[0]


def test_env_parsing(monkeypatch):
    import importlib

    monkeypatch.setenv("VAULT_LOW_PRIORITY_DIRS", " 3 Archive/ , ,Old/Stuff ")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.VAULT_LOW_PRIORITY_DIRS == ["3 Archive", "Old/Stuff"]
    finally:
        monkeypatch.delenv("VAULT_LOW_PRIORITY_DIRS")
        importlib.reload(config)


# --- vault_search_frontmatter sort_by / sort_order -------------------------------------

def _ids(results):
    return [r["frontmatter"].get("ID") for r in results]


@pytest.fixture
def id_vault(vault_dir):
    from obsidian_vault_mcp.server import frontmatter_index

    log = vault_dir / "Issues"
    log.mkdir()
    for n in (9, 10, 136, 99, 2):
        (log / f"issue-{n}.md").write_text(f"---\nID: BEANS-{n}\n---\nx\n")
    (log / "no-id.md").write_text("---\nStatus: Open\n---\nx\n")
    frontmatter_index.rebuild()
    return vault_dir


def _fm(**kwargs):
    from obsidian_vault_mcp.tools.search import vault_search_frontmatter
    return json.loads(vault_search_frontmatter(**kwargs))["results"]


def test_highest_id_in_one_call_uses_natural_order(id_vault):
    top = _fm(field="ID", match_type="exists", path_prefix="Issues", sort_by="ID", sort_order="desc", max_results=1)
    assert _ids(top) == ["BEANS-136"]


def test_ascending_natural_order(id_vault):
    res = _fm(field="ID", match_type="exists", path_prefix="Issues", sort_by="ID", max_results=50)
    assert _ids(res) == ["BEANS-2", "BEANS-9", "BEANS-10", "BEANS-99", "BEANS-136"]


def test_notes_missing_the_sort_field_go_last_both_ways(id_vault):
    for order in ("asc", "desc"):
        res = _fm(field="Status", match_type="exists", path_prefix="Issues", sort_by="ID", sort_order=order, max_results=50)
        assert res[-1]["path"].endswith("no-id.md")


def test_sorting_happens_before_truncation(id_vault):
    # Without sorting, max_results=1 returns whatever the index holds first; with it, always the max.
    for _ in range(3):
        assert _ids(_fm(field="ID", match_type="exists", sort_by="ID", sort_order="desc", max_results=1)) == ["BEANS-136"]


def test_mixed_types_do_not_raise():
    from obsidian_vault_mcp.tools.search import _natural_key
    values = ["v2.10", "v2.9", 7, 3.5, True, "abc"]
    sorted(values, key=_natural_key)
    assert sorted(["v2.10", "v2.9"], key=_natural_key) == ["v2.9", "v2.10"]


def test_sort_order_is_validated():
    from pydantic import ValidationError
    from obsidian_vault_mcp.models import VaultSearchFrontmatterInput
    with pytest.raises(ValidationError):
        VaultSearchFrontmatterInput(field="ID", sort_by="ID", sort_order="sideways")
