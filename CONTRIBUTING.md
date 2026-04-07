# Contributing to rekit

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/b-erdem/rekit.git
cd rekit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
pip install pytest ruff
```

## Running Tests

```bash
pytest                           # run all 646 tests
pytest tests/test_mockapi.py     # run tests for a specific tool
pytest -v --tb=short             # verbose with short tracebacks
```

## Code Style

We use [ruff](https://github.com/astral-sh/ruff) for formatting and linting:

```bash
ruff format .     # format all files
ruff check .      # lint all files
ruff check --fix  # auto-fix lint issues
```

Rules:
- Type hints on all public functions
- Docstrings on all public classes and functions
- `from __future__ import annotations` at the top of every module

## Adding a New Tool

1. Create a new package under `src/rekit/<toolname>/`
2. Add `__init__.py`, `cli.py` (typer subcommand group), and implementation modules
3. Register the subcommand in `src/rekit/cli.py`
4. Add tests under `tests/test_<toolname>.py`
5. Update `README.md` with usage examples
6. Update `CHANGELOG.md`
7. Run `ruff format . && ruff check . && pytest` before submitting

## Pull Requests

- One feature/fix per PR
- Include tests for new functionality
- Update CHANGELOG.md
- Run the full test suite before submitting

## Reporting Issues

Open an issue on GitHub with:
- What you were trying to do
- What happened
- Steps to reproduce
- Your Python version and OS
