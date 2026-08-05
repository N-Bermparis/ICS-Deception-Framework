# Contributing

Thanks for your interest in the ICS Deception Framework. This is an alpha research prototype, so
contributions that improve correctness, honesty of claims, test coverage or documentation are
especially welcome.

Please read [SECURITY.md](SECURITY.md) before contributing. **Do not report vulnerabilities in a
public issue or pull request** — use private disclosure.

## Ground rules

1. **Authorized research only.** Contributions must not add capabilities whose primary purpose is
   attacking systems the operator does not control. Deception, detection, telemetry and analysis are
   in scope; weaponised exploitation, mass scanning and evasion tooling are not.
2. **No overstated claims.** Never describe a component as standards compliant, production ready or
   peer reviewed unless there is evidence. If you extend the DNP3 sensor, it stays an *interaction
   sensor* until it actually implements DNP3.
3. **Safe defaults.** New services bind to loopback, use unprivileged ports, require no root, start
   nothing automatically and capture no plaintext secrets by default.
4. **No artifacts in git.** Never commit binaries, packet captures, runtime logs, caches,
   virtualenvs, local configuration or secrets.
5. **Never commit key material.** No private keys, no evidence archives, no chain state. Public test
   fixtures must be public-only and labelled as fixtures.
6. **No classical crypto fallback.** If you touch `pqc_evidence`, ML-DSA stays the only signature
   path. A missing provider must fail loudly, never degrade to RSA, ECDSA, Ed25519, HMAC or a mock.

## Development setup

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
make install-dev
```

## The checks

Everything must pass before a pull request is ready:

```bash
make check
```

That runs, in order:

| Step | Command |
|---|---|
| Byte-compile | `python -m compileall -q src tests scripts` |
| Lint | `python -m ruff check src tests scripts` |
| Native build | `make build` (`-Wall -Wextra -Wpedantic`) |
| Tests | `python -m pytest` |
| Shell syntax | `bash -n scripts/deploy_rpi.sh` |
| ShellCheck | `shellcheck scripts/deploy_rpi.sh` (where installed) |
| Packaging | `python -m build` |

CI additionally rebuilds the C++ sources with `-Werror`, so **any new compiler warning fails the
build**.

## Coding standards

### Python

- Target Python 3.10+; `from __future__ import annotations` at the top of modules.
- Ruff enforces `E`, `F`, `W`, `I`, `B`, `UP`, `C4`, `SIM` with a 100-column line length.
- Public functions, classes and modules get docstrings. Explain *why*, not *what*.
- Emit telemetry through `EventPublisher`, never with bare `print`.
- Resolve runtime paths through `ics_deception.common.paths` so deployments can relocate state.
- Bound anything attacker-influenced: payload samples, buffer sizes, session lengths, log values.

### C++

- C++17, POSIX sockets, no external dependencies.
- Must compile clean under `-Wall -Wextra -Wpedantic`.
- Validate every network-derived length and index *before* using it. Never trust a declared length.
- Use `icsd::send_all` for writes; a partial `send()` is a bug.
- Set receive timeouts and enforce client limits on any new listener.
- Shared helpers live in `src/native/common/`; keep header-only helpers `inline`, not `static`.

### Cryptographic code

- Everything under `src/ics_deception/pqc_evidence/` is security-relevant. Changes there need tests
  that demonstrate the *failure* is detected, not only that the happy path works.
- Never widen what the verifier accepts without a test showing why the wider case is sound.
- Attacker-controlled input must never raise an unexpected exception. Turn every parse failure into
  a structured `EvidenceValidationError`.
- Anything hashed or signed goes through `canonicalizer.canonical_bytes`. Never hash
  `json.dumps(...)` directly.
- Never log, print or serialise private key material — including in error messages and benchmarks.
- New alerts belong in `verifier.ALERTS` and in `docs/pqc-evidence-format.md`.

### Shell

- `#!/usr/bin/env bash` with `set -euo pipefail`.
- Quote every variable expansion. `bash -n` must pass.
- Never require root; never enable a service without an explicit flag.

## Tests

Add tests with every behavioural change. Tests must **not**:

- use privileged ports (bind port 0 and read back the assigned port),
- depend on randomness, wall-clock timing or an external network,
- leave processes running, or write into the repository — use pytest `tmp_path` and the
  `runtime_dir` fixture,
- require a C++ toolchain to *pass*; mark native tests with `@pytest.mark.integration` and skip
  cleanly when `make`/`g++` are unavailable,
- reuse a prebuilt binary from `build/`; use the `native_build` fixture, which compiles fresh so a
  stale binary cannot produce a false pass,
- leave key files, archives or chain state behind.

Tests needing real post-quantum cryptography use `@pytest.mark.pqc` and the `pqc_backend` fixture,
which skips with an explicit reason **only** when no provider is installed. CI runs a dedicated job
that fails if any PQC test skips — a green tick must never mean "everything was skipped".

Run the fast subset while iterating:

```bash
python -m pytest -m "not integration"
```

## Commits and pull requests

- Write imperative commit subjects: `Add MBAP length validation to the Python server`.
- Keep pull requests focused; unrelated refactors belong in their own PR.
- In the description, state what changed, why, how you tested it, and any new limitation.
- Update `CHANGELOG.md` under *Unreleased*, and update the README if behaviour or flags changed.
- If you add a service, document its protocol *incompleteness* in the README's Known limitations.

## Reporting bugs

Open an issue with: what you expected, what happened, the exact commands, your OS, Python and
compiler versions, and relevant JSONL events. **Redact addresses, credentials and capture data** —
never paste a real capture into an issue.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
