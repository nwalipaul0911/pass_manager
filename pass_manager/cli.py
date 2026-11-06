"""Command-line interface for creating and managing encrypted vaults."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from pass_manager.models import SECRET_TYPES, SecretEntry
from pass_manager.vault import Vault, VaultError, generate_password


def _prompt_password(prompt: str = "Master password: ", confirm: bool = False) -> str:
    """Prompt for a master password without echoing input to the terminal.

    Args:
        prompt: Text shown before the password prompt.
        confirm: If true, prompt for the password a second time and require an
            exact match.

    Returns:
        The entered, non-empty password.

    Raises:
        SystemExit: If the password is empty or confirmation does not match.
    """
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
    """Prompt for a non-empty secret without echoing it to the terminal.

    Args:
        prompt: Text shown before the secret prompt.

    Returns:
        The entered secret value.

    Raises:
        SystemExit: If the entered value is empty.
    """
    value = getpass.getpass(prompt)
    if not value:
        print("Secret value cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return value


def _mask(value: str, visible: int = 4) -> str:
    """Mask a string while optionally leaving its trailing characters visible.

    Args:
        value: Secret text to mask.
        visible: Number of trailing characters to leave visible when the value
            is longer than this number.

    Returns:
        A string of asterisks, followed by the visible suffix when applicable.
        Values no longer than ``visible`` are masked completely.
    """
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]


def _with_vault(args: argparse.Namespace, fn) -> int:
    """Unlock the selected vault and call a command-specific function.

    Args:
        args: Parsed CLI arguments; ``args.vault`` selects an optional vault
            path, with the default path used when it is falsey.
        fn: Callback accepting the unlocked :class:`Vault` and master password,
            and returning an integer command status.

    Returns:
        The callback's status code, or ``1`` if the vault is missing, cannot
        be unlocked, or raises a handled vault or value error. Errors are
        printed to standard error.
    """
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
    """Create a new encrypted vault at the selected path.

    Args:
        args: Parsed CLI arguments. ``args.vault`` is an optional path and
            ``args.force`` allows an existing vault file to be overwritten.

    Returns:
        ``0`` after creating the vault, or ``1`` if it already exists and
        ``--force`` was not supplied. Prompts for and confirms the master
        password, then prints the created path.
    """
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
    """Add a new secret entry to the selected vault.

    Args:
        args: Parsed CLI arguments containing the vault path, entry name,
            type, optional secret, username, URL, notes, and comma-separated
            tags. If no secret is supplied, the user is prompted for it.

    Returns:
        ``0`` if the entry is saved; otherwise, the status returned by
        :func:`_with_vault`. Prints a confirmation after saving.
    """
    def run(vault: Vault, master: str) -> int:
        """Create and save an entry using the parsed add-command options.

        Args:
            vault: The already-unlocked vault to modify.
            master: Master password used to encrypt the saved vault.

        Returns:
            ``0`` after saving the entry and printing its name and type.
        """
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
    """List vault entries, optionally filtered by type and search text.

    Args:
        args: Parsed CLI arguments containing the optional vault path, entry
            type filter, and text query.

    Returns:
        ``0`` after printing either the matching entries or a no-results
        message; otherwise, the status returned by :func:`_with_vault`.
        Secret values are not included in the output.
    """
    def run(vault: Vault, _master: str) -> int:
        """Print the matching entry metadata as a table.

        Args:
            vault: The already-unlocked vault to query.
            _master: Master password supplied by :func:`_with_vault`; unused.

        Returns:
            ``0`` after printing the table or a no-results message.
        """
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
    """Display one entry's details and optionally reveal its secret.

    Args:
        args: Parsed CLI arguments containing the vault path, entry name, and
            ``reveal`` flag.

    Returns:
        ``0`` after printing the entry, or the status returned by
        :func:`_with_vault`. The secret is masked unless ``--reveal`` is set.
    """
    def run(vault: Vault, _master: str) -> int:
        """Print one entry's available metadata and secret representation.

        Args:
            vault: The already-unlocked vault to query.
            _master: Master password supplied by :func:`_with_vault`; unused.

        Returns:
            ``0`` after printing the entry details.
        """
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
    """Print a single entry field to standard output.

    Args:
        args: Parsed CLI arguments containing the vault path, entry name, and
            selected field (``secret``, ``username``, or ``url``).

    Returns:
        ``0`` after printing the field, or the status returned by
        :func:`_with_vault`. This command is intended for shell pipelines.
    """
    def run(vault: Vault, _master: str) -> int:
        """Look up an entry and print its requested field.

        Args:
            vault: The already-unlocked vault to query.
            _master: Master password supplied by :func:`_with_vault`; unused.

        Returns:
            ``0`` after writing the selected value and a newline to standard
            output.
        """
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
    """Update the provided fields of an existing vault entry.

    Args:
        args: Parsed CLI arguments containing the vault path, current entry
            name, and optional replacement values for the entry's fields.
            An explicitly requested but empty secret triggers a hidden prompt.

    Returns:
        ``0`` after saving the update, ``1`` if no fields were supplied, or
        the status returned by :func:`_with_vault`. Prints a confirmation on
        success.
    """
    def run(vault: Vault, master: str) -> int:
        """Collect supplied replacement values and save them to the vault.

        Args:
            vault: The already-unlocked vault to modify.
            master: Master password used to encrypt the saved vault.

        Returns:
            ``0`` after a successful update, or ``1`` if no update fields
            were specified.
        """
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
    """Delete an entry, asking for confirmation unless ``--yes`` is set.

    Args:
        args: Parsed CLI arguments containing the vault path, entry name, and
            confirmation-skip flag.

    Returns:
        ``0`` after deletion or cancellation, or the status returned by
        :func:`_with_vault`. Prints whether the deletion completed or was
        cancelled.
    """
    def run(vault: Vault, master: str) -> int:
        """Confirm and delete the named entry from the unlocked vault.

        Args:
            vault: The already-unlocked vault to modify.
            master: Master password used to encrypt the saved vault.

        Returns:
            ``0`` after deletion or if the user declines confirmation.
        """
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
    """Search vault entries by passing the query to :func:`cmd_list`.

    Args:
        args: Parsed CLI arguments containing the vault path, required search
            query, and optional type filter.

    Returns:
        The status returned by :func:`cmd_list`, which prints matching entries
        without revealing their secret values.
    """
    args.query = args.query
    return cmd_list(args)


def cmd_gen(args: argparse.Namespace) -> int:
    """Generate a password and print it to standard output.

    Args:
        args: Parsed CLI arguments containing the requested length and flags
            controlling symbols and ambiguous characters.

    Returns:
        ``0`` after printing the generated password, or ``1`` if the requested
        length is invalid. Generation errors are printed to standard error.
    """
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
    """Print the selected vault path and its basic file status.

    Args:
        args: Parsed CLI arguments; ``args.vault`` may specify a non-default
            vault path.

    Returns:
        ``0`` after printing the path and existence status, plus file size if
        the vault exists.
    """
    vault = Vault(Path(args.vault) if args.vault else None)
    print(f"Vault path: {vault.path}")
    print(f"Exists:     {'yes' if vault.exists else 'no'}")
    if vault.exists:
        size = vault.path.stat().st_size
        print(f"Size:       {size} bytes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser and register the supported subcommands.

    Returns:
        An :class:`argparse.ArgumentParser` configured with global vault-path
        handling and the ``init``, ``add``, ``list``, ``show``, ``get``,
        ``update``, ``delete``, ``search``, ``gen``, and ``status`` commands.
        Each subcommand stores its handler in the parsed namespace's ``func``
        attribute.
    """
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
    """Parse CLI arguments and dispatch to the selected command handler.

    Args:
        argv: Optional argument strings to parse instead of ``sys.argv``.
            Useful when invoking the CLI programmatically or in tests.

    Returns:
        The integer status code returned by the selected command handler.
        The parser prints usage and exits for invalid arguments.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
