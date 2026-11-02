"""Escalating login lockout: per-address locks, a global backstop, and its admin commands.

Opt-in through OAUTH_LOCKOUT_SCHEDULE. Locks are kept in the OAuth store, so the store
tests check escalation, persistence and the schema upgrade, and the app tests check what
a caller sees through build_app(), the app the server runs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from io import StringIO
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from obsidian_vault_mcp import config, oauth, oauth_admin
from obsidian_vault_mcp.oauth_state import (
    GLOBAL_SUBJECT,
    SCHEMA_VERSION,
    LockoutPolicy,
    OAuthState,
)
from obsidian_vault_mcp.server import build_app

REDIRECT = "https://app.example/cb"
VERIFIER = "verifier-abc123_this-is-long-enough-for-pkce-xyz"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()

POLICY = LockoutPolicy(
    failures=3,
    window_seconds=600,
    schedule=(60.0, 3600.0, None),
    global_failures=10,
    global_window_seconds=600,
    global_lock_seconds=300,
)


# --- The store ---------------------------------------------------------------------------


@pytest.fixture
def now() -> list[float]:
    return [1_000_000.0]


@pytest.fixture
def store(tmp_path: Path, now: list[float]):
    state = OAuthState(tmp_path / "state" / "oauth_state.sqlite3", clock=lambda: now[0])
    yield state
    state.close()


def _fail(store: OAuthState, subject: str, times: int, policy: LockoutPolicy = POLICY):
    tripped = []
    for _ in range(times):
        tripped += store.record_login_failure(subject, policy)
    return tripped


def test_failures_below_the_limit_lock_nothing(store):
    assert _fail(store, "203.0.113.5", 2) == []
    assert store.active_lockout("203.0.113.5") is None


def test_each_trip_takes_the_next_step_and_the_last_is_permanent(store, now):
    first = _fail(store, "203.0.113.5", 3)
    assert [(lock.trips, lock.locked_until, lock.permanent) for lock in first] == [(1, now[0] + 60, False)]
    assert store.active_lockout("203.0.113.5").trips == 1

    now[0] += 61
    assert store.active_lockout("203.0.113.5") is None
    second = _fail(store, "203.0.113.5", 3)
    assert [(lock.trips, lock.locked_until) for lock in second] == [(2, now[0] + 3600)]

    now[0] += 3601
    third = _fail(store, "203.0.113.5", 3)
    assert [(lock.trips, lock.permanent, lock.locked_until) for lock in third] == [(3, True, None)]

    now[0] += 10 * 365 * 24 * 3600
    assert store.active_lockout("203.0.113.5").permanent


def test_failures_outside_the_window_do_not_count(store, now):
    _fail(store, "203.0.113.5", 2)
    now[0] += 601
    assert _fail(store, "203.0.113.5", 2) == []
    assert store.active_lockout("203.0.113.5") is None


def test_one_address_is_not_locked_by_another(store):
    _fail(store, "203.0.113.5", 3)
    assert store.active_lockout("198.51.100.7") is None


def test_a_correct_sign_in_starts_the_schedule_over(store, now):
    _fail(store, "203.0.113.5", 3)
    now[0] += 61
    store.record_login_success("203.0.113.5")

    again = _fail(store, "203.0.113.5", 3)

    assert [lock.trips for lock in again] == [1]


def test_the_global_limit_locks_every_address_but_never_permanently(store, now):
    for index in range(10):
        _fail(store, f"203.0.113.{index}", 1)

    lock = store.active_lockout("198.51.100.7")

    assert lock.subject == GLOBAL_SUBJECT
    assert not lock.permanent
    assert lock.locked_until == now[0] + 300
    now[0] += 301
    assert store.active_lockout("198.51.100.7") is None


def test_a_permanent_lock_outranks_a_global_one(store):
    _fail(store, "203.0.113.5", 3, POLICY.__class__(**{**POLICY.__dict__, "schedule": (None,)}))
    for index in range(10):
        _fail(store, f"198.51.100.{index}", 1)

    assert store.active_lockout("203.0.113.5").permanent


def test_locks_survive_reopening_the_store(tmp_path, now):
    path = tmp_path / "state" / "oauth_state.sqlite3"
    with OAuthState(path, clock=lambda: now[0]) as state:
        _fail(state, "203.0.113.5", 3)

    with OAuthState(path, clock=lambda: now[0]) as reopened:
        assert reopened.active_lockout("203.0.113.5").trips == 1


def test_unlock_lifts_one_subject_or_everything(store):
    _fail(store, "203.0.113.5", 3)
    _fail(store, "198.51.100.7", 3)

    assert store.unlock("203.0.113.5") == 1
    assert store.active_lockout("203.0.113.5") is None
    assert store.active_lockout("198.51.100.7") is not None
    assert store.unlock(None) == 1
    assert store.list_lockouts() == []


# --- Schema upgrade ----------------------------------------------------------------------


def test_a_version_1_store_is_upgraded_and_keeps_its_clients(tmp_path, now):
    path = tmp_path / "state" / "oauth_state.sqlite3"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(path)
    from obsidian_vault_mcp.oauth_state import _SCHEMA_V1
    connection.executescript(_SCHEMA_V1)
    connection.execute(
        "INSERT INTO clients (client_id, secret_verifier, is_static, client_name, created_at) "
        "VALUES ('kept', NULL, 0, 'Claude', 1.0)"
    )
    connection.execute("PRAGMA user_version = 1")
    connection.commit()
    connection.close()

    with OAuthState(path, clock=lambda: now[0]) as state:
        assert state.get_client("kept").client_name == "Claude"
        _fail(state, "203.0.113.5", 3)
        assert state.active_lockout("203.0.113.5") is not None

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 2
    connection.close()


def test_a_fresh_store_gets_every_table(tmp_path):
    path = tmp_path / "state" / "oauth_state.sqlite3"
    OAuthState(path).close()
    connection = sqlite3.connect(path)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    connection.close()

    assert {"clients", "access_tokens", "login_failures", "login_lockouts"} <= tables


# --- Subjects ----------------------------------------------------------------------------


@pytest.mark.parametrize("address,subject", [
    ("203.0.113.5", "203.0.113.5"),
    (" 203.0.113.5 ", "203.0.113.5"),
    ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:ffff::9", "2001:db8:1:2::/64"),
    ("::ffff:203.0.113.5", "203.0.113.5"),
    ("2001:db8:1:2::/64", "2001:db8:1:2::/64"),
    ("2001:db8:1:2::/128", "2001:db8:1:2::/64"),
    ("203.0.113.5/32", "203.0.113.5"),
])
def test_addresses_map_to_subjects(address, subject):
    assert oauth.lockout_subject(address) == subject


@pytest.mark.parametrize("address", ["", "not-an-ip", "203.0.113.0/24", "2001:db8::/48", "*",
                                     "203.0.113.5, 198.51.100.7"])
def test_anything_else_is_no_subject(address):
    assert oauth.lockout_subject(address) is None


# --- Settings ----------------------------------------------------------------------------


@pytest.fixture
def lockout_on(monkeypatch):
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_SCHEDULE", "60,3600,permanent")
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_FAILURES", "3")
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_WINDOW_SECONDS", "600")
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_GLOBAL_FAILURES", "10")
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_GLOBAL_WINDOW_SECONDS", "600")
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_GLOBAL_SECONDS", "300")
    monkeypatch.setattr(config, "OAUTH_CLIENT_IP_HEADER", "CF-Connecting-IP")
    monkeypatch.setattr(config, "VAULT_MCP_HOST", "127.0.0.1")


def test_the_mode_is_off_without_a_schedule(monkeypatch):
    monkeypatch.setattr(config, "OAUTH_LOCKOUT_SCHEDULE", "")
    assert config.lockout_policy() is None


def test_the_settings_parse_into_a_policy(lockout_on):
    assert config.lockout_policy() == POLICY


@pytest.mark.parametrize("setting,value,message", [
    ("OAUTH_LOCKOUT_SCHEDULE", "60,permanent,3600", "only be the last step"),
    ("OAUTH_LOCKOUT_SCHEDULE", "60,soon", "OAUTH_LOCKOUT_SCHEDULE step"),
    ("OAUTH_LOCKOUT_SCHEDULE", "0", "OAUTH_LOCKOUT_SCHEDULE step"),
    ("OAUTH_LOCKOUT_FAILURES", "0", "OAUTH_LOCKOUT_FAILURES"),
    ("OAUTH_LOCKOUT_GLOBAL_SECONDS", "-1", "OAUTH_LOCKOUT_GLOBAL_SECONDS"),
    ("OAUTH_CLIENT_IP_HEADER", "", "OAUTH_CLIENT_IP_HEADER"),
    ("VAULT_MCP_HOST", "0.0.0.0", "loopback"),
])
def test_a_bad_setting_fails_startup(lockout_on, monkeypatch, setting, value, message):
    monkeypatch.setattr(config, setting, value)
    with pytest.raises(ValueError, match=message):
        config.validate_config()


# --- Through the app ---------------------------------------------------------------------


@pytest.fixture
def clock(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(oauth, "_wall_clock", lambda: now[0])
    return now


@pytest.fixture
def app(vault_dir, monkeypatch, clock, lockout_on):
    oauth._auth_codes.clear()
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", "owner")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "correct-horse")
    yield TestClient(build_app(), base_url="https://vault.example")


def register(client):
    return client.post("/oauth/register", json={"client_name": "t", "redirect_uris": [REDIRECT]}).json()["client_id"]


def login(client, client_id, password, address="203.0.113.5"):
    data = {"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "s",
            "code_challenge": CHALLENGE, "code_challenge_method": "S256",
            "username": "owner", "password": password}
    headers = {} if address is None else {"CF-Connecting-IP": address}
    return client.post("/oauth/authorize", data=data, headers=headers, follow_redirects=False)


def test_a_mistyped_password_below_the_limit_is_a_plain_refusal(app):
    cid = register(app)
    for _ in range(2):
        assert login(app, cid, "wrong").status_code == 401

    assert login(app, cid, "correct-horse").status_code == 302


def test_a_locked_address_is_refused_even_with_the_password(app):
    cid = register(app)
    for _ in range(3):
        login(app, cid, "wrong")

    refused = login(app, cid, "correct-horse")

    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) == 60
    assert "Too many failed sign-in attempts" in refused.text
    assert "code=" not in (refused.headers.get("location") or "")


def test_another_address_still_signs_in(app):
    cid = register(app)
    for _ in range(3):
        login(app, cid, "wrong")

    assert login(app, cid, "correct-horse", address="198.51.100.7").status_code == 302


def test_the_lock_lifts_when_its_time_is_up(app, clock):
    cid = register(app)
    for _ in range(3):
        login(app, cid, "wrong")

    clock[0] += 61

    assert login(app, cid, "correct-horse").status_code == 302


def test_the_last_step_blocks_the_address_until_unlocked(app, clock):
    cid = register(app)
    for _ in range(3):
        for _ in range(3):
            login(app, cid, "wrong")
        clock[0] += 3601

    blocked = login(app, cid, "correct-horse")
    assert blocked.status_code == 403
    assert "blocked" in blocked.text

    oauth.get_oauth_state().unlock("203.0.113.5")
    assert login(app, cid, "correct-horse").status_code == 302


def test_a_sign_in_without_the_address_header_is_refused(app):
    cid = register(app)

    refused = login(app, cid, "correct-horse", address=None)

    assert refused.status_code == 400
    assert "code=" not in (refused.headers.get("location") or "")


def test_a_malformed_address_header_is_refused(app):
    cid = register(app)

    assert login(app, cid, "correct-horse", address="203.0.113.5, 198.51.100.7").status_code == 400


def test_ipv6_neighbours_in_one_slash_64_share_a_lock(app):
    cid = register(app)
    for host in ("1", "2", "3"):
        login(app, cid, "wrong", address=f"2001:db8:1:2::{host}")

    assert login(app, cid, "correct-horse", address="2001:db8:1:2::99").status_code == 429


# --- Admin command -----------------------------------------------------------------------


def _run(*argv):
    out, err = StringIO(), StringIO()
    code = oauth_admin.main(list(argv), stdout=out, stderr=err)
    return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()


def test_lockout_list_and_unlock(app):
    cid = register(app)
    for _ in range(3):
        login(app, cid, "wrong", address="2001:db8:1:2::1")
    oauth.close_oauth_state()  # the command opens the store itself, as it would beside a server

    code, listed, _ = _run("lockout", "list")
    assert code == 0
    assert [(entry["subject"], entry["trips"]) for entry in listed] == [("2001:db8:1:2::/64", 1)]

    code, result, _ = _run("lockout", "unlock", "2001:db8:1:2::abcd")
    assert (code, result) == (0, {"unlocked": "2001:db8:1:2::/64", "removed": 1})

    code, result, _ = _run("lockout", "unlock", "2001:db8:1:2::abcd")
    assert code == 1


def test_lockout_unlock_rejects_a_non_address():
    code, _, err = _run("lockout", "unlock", "nonsense")

    assert code == 1
    assert "not an IP address" in err


def test_lockout_unlock_all_and_global():
    state = oauth.get_oauth_state()
    for index in range(10):
        state.record_login_failure(f"203.0.113.{index}", POLICY)
    oauth.close_oauth_state()

    code, result, _ = _run("lockout", "unlock", "--global")
    assert (code, result["unlocked"]) == (0, "global")
    code, result, _ = _run("lockout", "unlock", "--all")
    assert code == 0
