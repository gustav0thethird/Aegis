# Contributing to Aegis

Thanks for taking the time to contribute. Aegis is early-stage and actively developed — external feedback and contributions directly shape what gets built next.

## Where to start

- **Browse open issues** — anything labelled `good first issue` or `help wanted` is fair game
- **Open a discussion** — if you have an idea or question, open a GitHub Discussion before writing code
- **Report bugs** — open an issue with steps to reproduce, expected behaviour, and actual behaviour

## What we most need

- Feedback from anyone running secrets infrastructure at scale, especially in regulated environments (financial services, healthcare, public sector)
- Additional vault backend integrations (Azure Key Vault, GCP Secret Manager, etc.)
- Testing on non-Linux platforms
- Security review — this is a security tool, scrutiny is welcome

## Development setup

```bash
git clone https://github.com/gustav0thethird/Aegis
cd Aegis

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Copy example config
cp config/auth.json.example config/auth.json

# Start dependencies
docker compose up -d db redis

# Run tests
pytest tests/
```

## Running the full stack locally

```bash
docker compose up
```

Alembic runs migrations on startup. API available at `http://localhost:8080`.

## Code style

- Python 3.12
- `ruff` for linting — run `ruff check .` before submitting
- `bandit` for security scanning — run `bandit -r aegis/ -ll`
- Keep changes focused — one concern per PR

## Pull requests

- Branch off `main`
- Use `feature/<name>`, `fix/<name>`, or `chore/<name>` naming
- Include a clear description of what changed and why
- Tests are expected for new functionality

## Licence

By contributing you agree that your contributions will be licensed under the project's [AGPLv3 licence](LICENSE).
