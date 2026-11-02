"""The vault-mcp-oauth command: OAuth clients and login lockouts in the local store.

`clients list|revoke` manages registered clients. `lockout list|unlock` shows and lifts
the escalating login lockouts (OAUTH_LOCKOUT_SCHEDULE); a permanent lock lifts only here.

It opens the same store the server uses, beside OAUTH_CLIENTS_PATH, importing the legacy
registry like every open, and it does so in Cloudflare Access mode too: this is local
administration, not a served endpoint. A revocation takes effect on a running server at
once, because every token lookup checks the client.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from typing import TextIO

from . import config
from .oauth import _state_path, lockout_subject
from .oauth_state import GLOBAL_SUBJECT, ClientMetadata, Lockout, OAuthState, OAuthStateError


# --- Arguments ---------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    """The command line of vault-mcp-oauth."""
    parser = argparse.ArgumentParser(
        prog="vault-mcp-oauth", description="List and revoke OAuth clients of the vault MCP server."
    )
    resources = parser.add_subparsers(dest="resource", required=True)
    clients = resources.add_parser("clients", help="Registered OAuth clients")
    actions = clients.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="List every client and whether it is revoked")
    revoke = actions.add_parser("revoke", help="Revoke a client; its tokens stop working")
    revoke.add_argument("client_id")
    lockout = resources.add_parser("lockout", help="Login lockouts")
    lockout_actions = lockout.add_subparsers(dest="action", required=True)
    lockout_actions.add_parser("list", help="List every locked or previously locked address")
    unlock = lockout_actions.add_parser("unlock", help="Lift a lock and forget its trips")
    target = unlock.add_mutually_exclusive_group(required=True)
    target.add_argument("address", nargs="?", help="An address, or an IPv6 /64 as listed")
    target.add_argument("--global", dest="global_lock", action="store_true",
                        help="Lift the lock on every address that the global limit set")
    target.add_argument("--all", action="store_true", help="Lift every lock and forget every trip")
    return parser


# --- Output ------------------------------------------------------------------------------


def _client_payload(client: ClientMetadata) -> dict[str, object]:
    """A client as printed: metadata only, the store holds no secret to print."""
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "created_at": client.created_at,
        "is_static": client.is_static,
        "last_authorized_at": client.last_authorized_at,
        "redirect_uris": list(client.redirect_uris),
        "revoked_at": client.revoked_at,
    }


def _lockout_payload(lock: Lockout, now: float) -> dict[str, object]:
    """A lockout as printed."""
    return {
        "subject": "global" if lock.subject == GLOBAL_SUBJECT else lock.subject,
        "trips": lock.trips,
        "permanent": lock.permanent,
        "locked_until": lock.locked_until,
        "active": lock.active(now),
    }


def _emit(stream: TextIO, payload: object) -> None:
    """Write one JSON line."""
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")


# --- Command -----------------------------------------------------------------------------


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Run one command and return its exit status."""
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    args = _parser().parse_args(argv)
    state: OAuthState | None = None
    try:
        state = OAuthState(_state_path(), legacy_path=config.OAUTH_CLIENTS_PATH)
        if args.resource == "lockout":
            return _lockout_command(args, state, output, errors)
        if args.action == "list":
            _emit(output, [_client_payload(client) for client in state.list_clients()])
            return 0
        revoked = state.revoke_client(args.client_id)
        _emit(output, {"client_id": args.client_id, "revoked": revoked})
        # Nothing to revoke (unknown or already revoked) is not a success a script can build on.
        return 0 if revoked else 1
    except (OSError, OAuthStateError, sqlite3.Error) as exc:
        _emit(errors, {"error": str(exc)})
        return 1
    finally:
        if state is not None:
            state.close()


def _lockout_command(args: argparse.Namespace, state: OAuthState, output: TextIO,
                     errors: TextIO) -> int:
    """lockout list | lockout unlock (address | --global | --all)."""
    if args.action == "list":
        now = time.time()
        _emit(output, [_lockout_payload(lock, now) for lock in state.list_lockouts()])
        return 0
    if args.all:
        _emit(output, {"unlocked": "all", "removed": state.unlock(None)})
        return 0
    if args.global_lock:
        subject = GLOBAL_SUBJECT
    else:
        subject = lockout_subject(args.address)
        if subject is None:
            _emit(errors, {"error": f"not an IP address: {args.address!r}"})
            return 1
    removed = state.unlock(subject)
    _emit(output, {"unlocked": "global" if subject == GLOBAL_SUBJECT else subject, "removed": removed})
    # Nothing to lift is not a success a script can build on.
    return 0 if removed else 1


def _entrypoint() -> None:
    """Console script entry point."""
    raise SystemExit(main())
