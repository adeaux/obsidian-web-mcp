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
