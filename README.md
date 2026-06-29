# pass-manager

A terminal-based secret manager for passwords, API keys, and other sensitive values. Secrets are stored in an encrypted vault file protected by a single master password.

## Features

- Encrypted local vault (AES-256 via Fernet)
- Master password derived with PBKDF2-HMAC-SHA256 (600,000 iterations)
- Secret types: `password`, `api_key`, `note`, `other`
- Optional metadata: username, URL, notes, tags
- Search and filter by type or keyword
- Secure password generator
- Script-friendly `get` command for shell pipelines

## Requirements

- Python 3.10+
- [cryptography](https://pypi.org/project/cryptography/) 42.0+

## Installation

Clone the repository and install in editable mode:

```bash
git clone <repo-url>
cd pass_manager
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Or install dependencies only:

```bash
pip install -r requirements.txt
python -m pass_manager --help
```

After installation, the `pass-manager` command is available on your PATH.

## Quick start

```bash
# Create a new vault (prompts for master password)
pass-manager init

# Add secrets
pass-manager add github -t password -u myuser --url https://github.com
pass-manager add openai -t api_key --notes "Production key"

# List and view
pass-manager list
pass-manager show github
pass-manager show github --reveal

# Search
pass-manager search git

# Generate a password
pass-manager gen -l 24
```

## Vault location

By default, the encrypted vault is stored at:

```
~/.local/share/pass_manager/vault.enc
```

Override the path with the `PASS_MANAGER_VAULT` environment variable or the global `--vault` flag:

```bash
export PASS_MANAGER_VAULT=/path/to/my-vault.enc
pass-manager list
```

Check vault status without unlocking:

```bash
pass-manager status
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new encrypted vault |
| `add <name>` | Add a secret |
| `list` / `ls` | List all secrets |
| `show <name>` | Show secret details (masked by default) |
| `get <name>` | Print a field to stdout (for scripts) |
| `update <name>` | Update an existing secret |
| `delete <name>` / `rm` | Delete a secret |
| `search <query>` | Search by name, username, URL, notes, or tags |
| `gen` | Generate a secure random password |
| `status` | Show vault path and whether it exists |

Most commands prompt for your master password. `init`, `gen`, and `status` do not require an unlocked vault.

### Add

```bash
pass-manager add <name> [options]

Options:
  -t, --type      Secret type: password, api_key, note, other (default: password)
  -s, --secret    Secret value (prompted securely if omitted)
  -u, --username  Associated username or email
  --url           Associated URL
  --notes         Free-form notes
  --tags          Comma-separated tags
```

### List

```bash
pass-manager list [-t TYPE] [-q QUERY]
```

### Show

```bash
pass-manager show <name> [-r|--reveal]
```

Without `--reveal`, the secret value is partially masked.

### Get

Print a single field for use in scripts:

```bash
pass-manager get github -f secret    # default field
pass-manager get github -f username
pass-manager get github -f url
```

### Update

```bash
pass-manager update <name> [--name NEW_NAME] [-t TYPE] [-s SECRET] [-u USERNAME] [--url URL] [--notes NOTES] [--tags TAGS]
```

Omit `-s` entirely to leave the secret unchanged. Pass `-s` alone to be prompted for a new value.

### Delete

```bash
pass-manager delete <name> [-y|--yes]
```

### Generate password

```bash
pass-manager gen [-l LENGTH] [--no-symbols] [--ambiguous]
```

Default length is 20. Ambiguous characters (`0`, `O`, `1`, `l`, etc.) are excluded unless `--ambiguous` is passed.

## Examples

```bash
# Store a GitHub personal access token
pass-manager add github-token -t api_key -u myuser \
  --url https://github.com --tags dev,git

# Store a login with a generated password
pass-manager add email -t password -u me@example.com \
  -s "$(pass-manager gen -l 32)"

# Filter by type
pass-manager list -t api_key

# Rename a secret
pass-manager update old-name --name new-name

# Delete without confirmation prompt
pass-manager delete old-name -y
```

## Security

- The master password is never written to disk.
- Each vault file uses a unique random salt; the encryption key is derived at unlock time.
- Wrong master passwords fail decryption with a clear error — there is no password hint or recovery mechanism. **Back up your master password.**
- The vault file is created with restrictive permissions (`0600`) where the OS supports it.
- Secret values are hidden by default in `show`; use `--reveal` only when needed.
- Avoid passing secrets on the command line (`-s`) in shared environments — they may appear in shell history. Prefer the interactive prompt instead.

## Project structure

```
pass_manager/
├── pass_manager/
│   ├── cli.py      # Command-line interface
│   ├── vault.py    # Vault CRUD and password generation
│   ├── crypto.py   # Encryption and key derivation
│   └── models.py   # Secret entry data model
├── pyproject.toml
└── requirements.txt
```
