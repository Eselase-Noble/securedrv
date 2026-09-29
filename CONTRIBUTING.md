# Contributing to Cipherjet

Thanks for your interest in improving Cipherjet.

## Getting set up

```bash
git clone https://github.com/Eselase-Noble/securedrv.git && cd securedrv
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Workflow

1. Branch off `production`.
2. Make your change, keeping the surrounding code style and comment density.
3. Run the tests (`ctest --test-dir build`). Add tests for new behaviour.
4. Open a pull request. The template will prompt you for a summary and checklist.

## What runs automatically on every pull request

- **CI** builds and tests on Linux, macOS and Windows.
- **Static analysis** (cppcheck) flags bugs and code smells.
- **CodeQL** performs a security code review; results appear in the Security tab.
- **Dependabot** opens PRs to keep GitHub Actions up to date.

## Reporting issues

- Bugs and features: open an issue using the provided templates.
- Security vulnerabilities: please report privately via
  [Security Advisories](https://github.com/Eselase-Noble/securedrv/security/advisories/new),
  not as public issues.
