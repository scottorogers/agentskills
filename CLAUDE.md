# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repo defines the **Agent Skills** open format — a spec for giving AI agents new capabilities via `SKILL.md` files. It contains three main components:

- **`docs/`** — The [agentskills.io](https://agentskills.io) documentation site (Mintlify)
- **`skills-ref/`** — A Python reference library for validating and working with skills
- **Root** — Spec governance, contributing guidelines, and repo-level config

Each subdirectory has its own `CLAUDE.md` with component-specific notes.

## Commands

### Documentation Site (`docs/`)

```bash
# Run local dev server (from repo root)
npm run dev
# Or directly:
cd docs && mint dev
```

Preview at `http://localhost:3000`. Deployment is automatic on push to `main`.

### Reference Library (`skills-ref/`)

```bash
# Install dependencies
cd skills-ref && uv sync

# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_parser.py

# Format and lint
uv run ruff format .
uv run ruff check --fix .

# CLI usage (after install)
skills-ref validate path/to/skill
skills-ref read-properties path/to/skill
skills-ref to-prompt path/to/skill-a path/to/skill-b
```

## Architecture

### Skill Format

A skill is a directory with a `SKILL.md` file containing YAML frontmatter + Markdown instructions. Required frontmatter fields: `name` (lowercase, hyphens only, matches directory name) and `description`. Optional: `license`, `compatibility`, `metadata`, `allowed-tools`.

Agents load skills progressively: metadata (~100 tokens) at startup → full `SKILL.md` body on activation → referenced files (scripts/references/assets) on demand.

### `skills-ref/` Library Structure

- `models.py` — Pydantic-style data models for skill properties
- `parser.py` — Parses `SKILL.md` YAML frontmatter via `strictyaml`
- `validator.py` — Validates parsed skill properties against spec rules
- `prompt.py` — Generates `<available_skills>` XML for agent system prompts
- `cli.py` — Click-based CLI wrapping the above
- `errors.py` — Shared error types

### Documentation Structure

Navigation is defined in `docs/docs.json`. To add a page: create a `.mdx` file in `docs/`, then add its filename (without extension) to the `navigation.pages` array.

## Contributing Notes

- PRs must disclose AI assistance used (see `CONTRIBUTING.md`). This applies to this session.
- The reference library (`skills-ref/`) is not accepting code contributions currently — bugs go to Issues, feedback to Discussions.
- Ecosystem/logo listings go in `docs/snippets/clients.jsx`; follow the existing format.
