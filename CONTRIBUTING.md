# Contributing to rekit

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/b-erdem/rekit.git
cd rekit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

## Running Tests

```bash
pytest
```

## Code Style

- Type hints on all public functions
- Docstrings on all public classes and functions
- `from __future__ import annotations` at the top of every module

## Adding a New Tool

1. Create a new package under `src/rekit/<toolname>/`
2. Add `__init__.py`, `cli.py` (typer subcommand group), and implementation modules
3. Register the subcommand in `src/rekit/cli.py`
4. Add tests under `tests/test_<toolname>/`
5. Update `README.md` with usage examples

## Pull Requests

- One feature/fix per PR
- Include tests for new functionality
- Update CHANGELOG.md
- Run `pytest` before submitting

## Reporting Issues

Open an issue on GitHub with:
- What you were trying to do
- What happened
- Steps to reproduce
- Your Python version and OS
