# Contributing to SQLi Detection Lab

Thank you for contributing to `sqlilab`!

## Code Quality Standards
- Strict typing with `mypy` (0 errors).
- Clean formatting and linting with `ruff` (`line-length = 100`).
- Zero security issues detected by `bandit`.
- Minimum test coverage requirement: $\ge 90\%$.
- Test all new detection rules against both malicious attack vectors and legitimate benign inputs (e.g. O'Connor, search queries).
