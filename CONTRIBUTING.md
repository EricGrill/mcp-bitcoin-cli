# Contributing to MCP Bitcoin CLI

We love your input! We want to make contributing to MCP Bitcoin CLI as easy and transparent as possible.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-bitcoin-cli.git
cd mcp-bitcoin-cli

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_bitcoin_cli

# Run specific test
pytest tests/test_envelope.py
```

## Code Quality

```bash
# Format code
ruff format .

# Check linting
ruff check .

# Type checking
mypy src/
```

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update CHANGELOG.md with your changes
3. Ensure all tests pass
4. The PR will be merged once you have the sign-off of a maintainer

## Code Style Guidelines

- Follow PEP 8
- Use type hints for all function signatures
- Write docstrings for public functions
- Keep functions focused on a single responsibility

## Reporting Bugs

Report bugs using GitHub Issues. Please include:
- Python version
- Bitcoin Core version (if applicable)
- Steps to reproduce
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
