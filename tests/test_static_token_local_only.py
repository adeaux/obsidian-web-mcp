"""VAULT_MCP_TOKEN_LOCAL_ONLY: the static token works only on requests made on this machine."""

import logging

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp import config

STATIC = "secret-token"
BEARER = {"Authorization": f"Bearer {STATIC}"}


def make_client(monkeypatch, *, local_only, peer="127.0.0.1"):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", STATIC)
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN_LOCAL_ONLY", local_only)

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    return TestClient(app, client=(peer, 50000))


def test_off_by_default():
    assert config.VAULT_MCP_TOKEN_LOCAL_ONLY is False


def test_off_the_static_token_works_through_a_proxy(monkeypatch):
    client = make_client(monkeypatch, local_only=False)
    r = client.get("/", headers={**BEARER, "CF-Connecting-IP": "203.0.113.9"})
    assert r.status_code == 200


@pytest.mark.parametrize("peer", ["127.0.0.1", "::1"])
def test_on_a_direct_local_request_is_accepted(monkeypatch, peer):
    client = make_client(monkeypatch, local_only=True, peer=peer)
    assert client.get("/", headers=BEARER).status_code == 200


@pytest.mark.parametrize("header", [
    {"CF-Connecting-IP": "203.0.113.9"},
    {"cf-ray": "8f00000000000000-EWR"},
    {"X-Forwarded-For": "203.0.113.9"},
    {"Forwarded": "for=203.0.113.9"},
    {"X-Real-IP": "203.0.113.9"},
])
def test_on_a_relayed_request_is_refused_like_a_wrong_token(monkeypatch, caplog, header):
    client = make_client(monkeypatch, local_only=True)
    with caplog.at_level(logging.WARNING, logger=auth_module.__name__):
        refused = client.get("/", headers={**BEARER, **header})
    wrong = client.get("/", headers={"Authorization": "Bearer wrong", **header})
    assert refused.status_code == 401
    assert refused.json() == wrong.json()
    assert refused.headers["WWW-Authenticate"] == wrong.headers["WWW-Authenticate"]
    assert "Static token refused" in caplog.text
    assert STATIC not in caplog.text


def test_on_the_configured_address_header_counts_as_a_proxy(monkeypatch):
    monkeypatch.setattr(config, "OAUTH_CLIENT_IP_HEADER", "X-Custom-Client")
    client = make_client(monkeypatch, local_only=True)
    assert client.get("/", headers={**BEARER, "X-Custom-Client": "203.0.113.9"}).status_code == 401


def test_on_a_non_loopback_peer_is_refused(monkeypatch):
    client = make_client(monkeypatch, local_only=True, peer="192.168.1.50")
    assert client.get("/", headers=BEARER).status_code == 401


def test_on_a_wrong_token_from_local_is_still_refused(monkeypatch):
    client = make_client(monkeypatch, local_only=True)
    assert client.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 401
