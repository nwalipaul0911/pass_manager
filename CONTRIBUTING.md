# Contributing to pass-manager

Thanks for your interest in pass-manager!

## Ways to get involved

1. **Open an issue** — report bugs, suggest features, or ask questions.
2. **Submit a pull request** — fork the repo, make your changes, and open a PR against `main`.
3. **Request collaboration** — use the [collaboration request template](https://github.com/nwalipaul0911/pass_manager/issues/new?template=collaboration_request.yml) if you'd like to discuss a larger contribution or co-maintaining.

## Development setup

```bash
git clone https://github.com/nwalipaul0911/pass_manager.git
cd pass_manager
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Pull request guidelines

- Keep changes focused — one feature or fix per PR.
- Match existing code style and conventions.
- Test CLI commands manually before submitting.
- Do not commit secrets, vault files, or `.env` files.

## Security

If you discover a security vulnerability, please open a private issue or contact the maintainer directly rather than filing a public bug report.
