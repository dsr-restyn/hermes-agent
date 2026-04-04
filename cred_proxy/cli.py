"""CLI for the credential proxy daemon.

Standalone entry point (``hermes-cred-proxy``):
  hermes-cred-proxy start
  hermes-cred-proxy stop
  hermes-cred-proxy status
  hermes-cred-proxy add <name>     (prompts for value, never echoes it)
  hermes-cred-proxy list

Also callable from the main hermes CLI as ``hermes cred-proxy <subcommand>``.
Use dispatch(args) for that path where args.cred_proxy_command is set.
"""

import argparse
import getpass
import sys


# ---------------------------------------------------------------------------
# Individual command implementations
# ---------------------------------------------------------------------------

def cmd_start(args=None) -> None:
    from cred_proxy.daemon import start
    start()


def cmd_stop(args=None) -> None:
    from cred_proxy.daemon import stop
    stop()


def cmd_status(args=None) -> None:
    from cred_proxy.daemon import status
    info = status()
    if info["running"]:
        print(f"running (PID {info['pid']})")
    else:
        print("stopped")
    print(f"address: {info['address']}")


def cmd_add(args) -> None:
    name = args.name
    try:
        value = getpass.getpass(f"Value for {name!r}: ")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        sys.exit(1)
    if not value:
        print("Error: empty value not allowed.")
        sys.exit(1)
    from cred_proxy.store import CredStore
    store = CredStore()
    store.set(name, value)
    print(f"Stored credential {name!r}.")


def cmd_list(args=None) -> None:
    from cred_proxy.store import CredStore
    store = CredStore()
    names = store.list()
    if not names:
        print("(no credentials stored)")
    else:
        for n in names:
            print(n)


# ---------------------------------------------------------------------------
# Dispatcher (used by hermes cred-proxy subcommand in main.py)
# ---------------------------------------------------------------------------

def dispatch(args) -> None:
    """Route args.cred_proxy_command to the appropriate handler."""
    cmd = getattr(args, "cred_proxy_command", None)
    if cmd == "start":
        cmd_start(args)
    elif cmd == "stop":
        cmd_stop(args)
    elif cmd == "status":
        cmd_status(args)
    elif cmd == "add":
        cmd_add(args)
    elif cmd == "list":
        cmd_list(args)
    else:
        # No subcommand: print help
        print("Usage: hermes cred-proxy {start,stop,status,add,list}")
        print("       hermes-cred-proxy {start,stop,status,add,list}")


# ---------------------------------------------------------------------------
# Standalone argparse CLI (hermes-cred-proxy entry point)
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermes-cred-proxy",
        description="Hermes credential proxy — store and inject secrets into tool subprocesses",
    )
    subs = parser.add_subparsers(dest="subcommand", help="Command")

    subs.add_parser("start", help="Start the credential proxy daemon")
    subs.add_parser("stop", help="Stop the credential proxy daemon")
    subs.add_parser("status", help="Show daemon status")

    add_p = subs.add_parser("add", help="Add or update a named credential")
    add_p.add_argument("name", help="Credential name (used in hermes-proxy://<name>)")

    subs.add_parser("list", help="List stored credential names")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.subcommand == "start":
        cmd_start(args)
    elif args.subcommand == "stop":
        cmd_stop(args)
    elif args.subcommand == "status":
        cmd_status(args)
    elif args.subcommand == "add":
        cmd_add(args)
    elif args.subcommand == "list":
        cmd_list(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
