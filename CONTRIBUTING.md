# Contributing to n3rve

Thank you for considering contributing to n3rve! This is a security-focused WPA/WPA2 passphrase recovery tool. Please read this guide before submitting changes.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Install development dependencies: `pip install -r requirements-dev.txt`
4. Make your changes
5. Run linting and tests: `ruff check . && pytest tests/`
6. Commit with a clear message: `git commit -m "feat: describe your change"`
7. Push and open a Pull Request

## Code Style

- Python 3.10+
- [Ruff](https://github.com/astral-sh/ruff) for linting (configured in `pyproject.toml`)
- Type hints where practical
- Docstrings on public functions and classes
- Follow the existing code style in `src/`

## Testing

The project includes 200+ unit tests in `tests/`. All tests must pass before a PR is merged:

```bash
pytest tests/
```

## Security

n3rve is a security tool. If you discover a vulnerability, please see [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Legal / Ethical

- Only contribute code you have the right to contribute
- Do not add copyrighted wordlists or proprietary ISP keygen algorithms without proper attribution
- All contributions must align with the authorized-use-only disclaimer

## Recognition

Contributors are acknowledged in the release notes. Thank you for helping improve n3rve!
