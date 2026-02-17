# Contributing to Project Artemis

Thank you for your interest in contributing! This document provides guidelines for contributing to Project Artemis.

## 🔒 Security First

Before submitting any code, ensure:

1. **No hardcoded credentials** — API keys, passwords, tokens
2. **No personal information** — Real IPs, email addresses, usernames
3. **No internal paths** — Use relative paths or environment variables
4. **No sensitive configs** — Use `.example` files for configuration templates

## 🚀 Getting Started

### Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/project-artemis.git
cd project-artemis
```

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

## 📝 Making Changes

### Branch Naming

- `feature/description` — New features
- `fix/description` — Bug fixes
- `docs/description` — Documentation only
- `refactor/description` — Code refactoring

### Code Style

We use:
- **Black** for formatting
- **Ruff** for linting
- **mypy** for type checking

```bash
# Format code
black src tests

# Check linting
ruff check src tests

# Type check
mypy src
```

### Commit Messages

Use conventional commits:

```
feat: Add new detection format
fix: Resolve network scanning timeout
docs: Update EDR documentation
refactor: Simplify threat intel loading
```

## ✅ Pull Request Checklist

- [ ] Code follows existing style
- [ ] Tests pass (`pytest`)
- [ ] No sensitive data (IPs, keys, personal info)
- [ ] Documentation updated if needed
- [ ] Commit messages are clear

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/artemis

# Run specific test file
pytest tests/test_generators.py
```

## 📁 Project Structure

When adding new features:

- **Detection formats** → `src/artemis/generators/`
- **EDR components** → `src/artemis/edr/`
- **Network features** → `src/artemis/agent/`
- **API endpoints** → `src/artemis/web/app.py`
- **CLI commands** → `src/artemis/cli.py`

## 🐛 Reporting Bugs

Open an issue with:
1. Description of the bug
2. Steps to reproduce
3. Expected vs actual behavior
4. Environment (OS, Python version)

## 💡 Feature Requests

Open an issue with:
1. Description of the feature
2. Use case / why it's useful
3. Possible implementation approach

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Questions? Open an issue or start a discussion!
