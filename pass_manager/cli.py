from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from pass_manager.models import SECRET_TYPES, SecretEntry
from pass_manager.vault import Vault, VaultError, generate_password


def _prompt_password(prompt: str = "Master password: ", confirm: bool = False) -> str:
    password = getpass.getpass(prompt)
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if password != again:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return password


def _prompt_secret(prompt: str = "Secret value: ") -> str:
    value = getpass.getpass(prompt)
    if not value:
        print("Secret value cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return value


def _mask(value: str, visible: int = 4) -> str:
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]


def _with_vault(args: argparse.Namespace, fn) -> int:
    vault = Vault(Path(args.vault) if args.vault else None)
    try:
        if not vault.exists:
            print(
                f"No vault at {vault.path}. Run 'pass-manager init' first.",
                file=sys.stderr,
            )
            return 1
        master = _prompt_password()
        vault.unlock(master)
        return fn(vault, master)
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_init(args: argparse.Namespace) -> int:
    vault = Vault(Path(args.vault) if args.vault else None)
    if vault.exists and not args.force:
        print(
            f"Vault already exists at {vault.path}. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1
    master = _prompt_password(confirm=True)
    if vault.exists and args.force:
        vault.path.unlink()
    vault.create(master)
    print(f"Vault created at {vault.path}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    def run(vault: Vault, master: str) -> int:
        secret = args.secret or _prompt_secret()
        entry = SecretEntry(
            name=args.name,
            secret_type=args.type,
            secret=secret,
            username=args.username or "",
            url=args.url or "",
            notes=args.notes or "",
            tags=[t.strip() for t in (args.tags or "").split(",") if t.strip()],
        )
        vault.add(entry, master)
        print(f"Added '{entry.name}' ({entry.secret_type})")
        return 0

    return _with_vault(args, run)


def cmd_list(args: argparse.Namespace) -> int:
    def run(vault: Vault, _master: str) -> int:
        entries = vault.list_entries(secret_type=args.type, query=args.query)
        if not entries:
            print("No secrets found.")
            return 0
        name_w = max(len("NAME"), max(len(e.name) for e in entries))
        print(f"{'NAME':<{name_w}}  {'TYPE':<10}  USERNAME  URL")
        print("-" * (name_w + 30))
        for e in entries:
            username = e.username or "-"
            url = e.url or "-"
            print(f"{e.name:<{name_w}}  {e.secret_type:<10}  {username}  {url}")
        print(f"\n{len(entries)} secret(s)")
        return 0

    return _with_vault(args, run)


def cmd_show(args: argparse.Namespace) -> int:
    def run(vault: Vault, _master: str) -> int:
        entry = vault.get(args.name)
        print(f"Name:     {entry.name}")
        print(f"Type:     {entry.secret_type}")
        if entry.username:
            print(f"Username: {entry.username}")
        if entry.url:
            print(f"URL:      {entry.url}")
        if entry.tags:
            print(f"Tags:     {', '.join(entry.tags)}")
        if entry.notes:
            print(f"Notes:    {entry.notes}")
        if args.reveal:
            print(f"Secret:   {entry.secret}")
        else:
            print(f"Secret:   {_mask(entry.secret)}")
            print("(use --reveal to show the full secret)")
        print(f"Created:  {entry.created_at}")
        print(f"Updated:  {entry.updated_at}")
        return 0

    return _with_vault(args, run)


def cmd_get(args: argparse.Namespace) -> int:
    def run(vault: Vault, _master: str) -> int:
        entry = vault.get(args.name)
        if args.field == "secret":
            print(entry.secret)
        elif args.field == "username":
            print(entry.username)
        elif args.field == "url":
            print(entry.url)
        else:
            print(entry.secret)
        return 0

    return _with_vault(args, run)


def cmd_update(args: argparse.Namespace) -> int:
    def run(vault: Vault, master: str) -> int:
        fields: dict = {}
        if args.name_new:
            fields["name"] = args.name_new
        if args.type:
            fields["secret_type"] = args.type
        if args.secret is not None:
            fields["secret"] = args.secret or _prompt_secret("New secret value: ")
        if args.username is not None:
            fields["username"] = args.username
        if args.url is not None:
            fields["url"] = args.url
        if args.notes is not None:
            fields["notes"] = args.notes
        if args.tags is not None:
            fields["tags"] = [t.strip() for t in args.tags.split(",") if t.strip()]
        if not fields:
            print("Nothing to update. Provide at least one field.", file=sys.stderr)
            return 1
        entry = vault.update(args.name, master, **fields)
        print(f"Updated '{entry.name}'")
        return 0

    return _with_vault(args, run)


def cmd_delete(args: argparse.Namespace) -> int:
    def run(vault: Vault, master: str) -> int:
        if not args.yes:
            confirm = input(f"Delete '{args.name}'? [y/N] ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Cancelled.")
                return 0
        vault.delete(args.name, master)
        print(f"Deleted '{args.name}'")
        return 0

    return _with_vault(args, run)


def cmd_search(args: argparse.Namespace) -> int:
    args.query = args.query
    return cmd_list(args)


def cmd_gen(args: argparse.Namespace) -> int:
    try:
        password = generate_password(
            length=args.length,
            symbols=not args.no_symbols,
            exclude_ambiguous=not args.ambiguous,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(password)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    vault = Vault(Path(args.vault) if args.vault else None)
    print(f"Vault path: {vault.path}")
    print(f"Exists:     {'yes' if vault.exists else 'no'}")
    if vault.exists:
        size = vault.path.stat().st_size
        print(f"Size:       {size} bytes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pass-manager",
        description="Terminal secret manager for passwords, API keys, and more.",
    )
    parser.add_argument(
        "--vault",
        help="Path to vault file (default: ~/.local/share/pass_manager/vault.enc)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a new encrypted vault")
    p_init.add_argument(
        "--force", action="store_true", help="Overwrite existing vault"
    )
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Add a new secret")
    p_add.add_argument("name", help="Secret name")
    p_add.add_argument(
        "-t",
        "--type",
        choices=SECRET_TYPES,
        default="password",
        help="Secret type (default: password)",
    )
    p_add.add_argument("-s", "--secret", help="Secret value (prompted if omitted)")
    p_add.add_argument("-u", "--username", help="Associated username or email")
    p_add.add_argument("--url", help="Associated URL")
    p_add.add_argument("--notes", help="Notes")
    p_add.add_argument("--tags", help="Comma-separated tags")
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", aliases=["ls"], help="List secrets")
    p_list.add_argument("-t", "--type", choices=SECRET_TYPES, help="Filter by type")
    p_list.add_argument("-q", "--query", help="Filter by search query")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show secret details")
    p_show.add_argument("name", help="Secret name")
    p_show.add_argument(
        "-r", "--reveal", action="store_true", help="Reveal the full secret value"
    )
    p_show.set_defaults(func=cmd_show)

    p_get = sub.add_parser("get", help="Print a secret field (for scripts)")
    p_get.add_argument("name", help="Secret name")
    p_get.add_argument(
        "-f",
        "--field",
        choices=("secret", "username", "url"),
        default="secret",
        help="Field to print (default: secret)",
    )
    p_get.set_defaults(func=cmd_get)

    p_update = sub.add_parser("update", help="Update an existing secret")
    p_update.add_argument("name", help="Current secret name")
    p_update.add_argument("--name", dest="name_new", help="New name")
    p_update.add_argument("-t", "--type", choices=SECRET_TYPES, help="New type")
    p_update.add_argument("-s", "--secret", nargs="?", const="", help="New secret")
    p_update.add_argument("-u", "--username", help="New username")
    p_update.add_argument("--url", help="New URL")
    p_update.add_argument("--notes", help="New notes")
    p_update.add_argument("--tags", help="New comma-separated tags")
    p_update.set_defaults(func=cmd_update)

    p_delete = sub.add_parser("delete", aliases=["rm"], help="Delete a secret")
    p_delete.add_argument("name", help="Secret name")
    p_delete.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    p_delete.set_defaults(func=cmd_delete)

    p_search = sub.add_parser("search", help="Search secrets by keyword")
    p_search.add_argument("query", help="Search term")
    p_search.add_argument("-t", "--type", choices=SECRET_TYPES, help="Filter by type")
    p_search.set_defaults(func=cmd_search)

    p_gen = sub.add_parser("gen", help="Generate a secure random password")
    p_gen.add_argument("-l", "--length", type=int, default=20, help="Length (default: 20)")
    p_gen.add_argument(
        "--no-symbols", action="store_true", help="Exclude symbols"
    )
    p_gen.add_argument(
        "--ambiguous",
        action="store_true",
        help="Include ambiguous characters (0, O, 1, l, etc.)",
    )
    p_gen.set_defaults(func=cmd_gen)

    p_status = sub.add_parser("status", help="Show vault location and status")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
