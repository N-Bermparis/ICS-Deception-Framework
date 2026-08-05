# GitHub Upload Checklist

Run through this before the first push, and again before any release. Commands assume a POSIX shell
at the repository root.

## 1. No artifacts, captures, logs or secrets

- [ ] No compiled binaries or object files

```bash
find . -path ./.git -prune -o \( -name '*.o' -o -name '*.so' -o -name '*.a' -o -name '*.exe' \) -print
```

- [ ] No packet captures anywhere in the tree

```bash
find . -path ./.git -prune -o \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) -print
```

- [ ] No runtime logs or state

```bash
find . -path ./.git -prune -o \( -name '*.jsonl' -o -name '*.log' -o -name 'plc_state.json' \) -print
```

- [ ] No private keys, evidence archives or chain state

```bash
find . -path ./.git -prune -o \( -name '*.key' -o -name '*.pem' -o -name '*.pqcarch' -o -name 'id_rsa*' -o -path './keys/*' -o -path './archives/*' \) -print
```

```bash
grep -rl -- "-----BEGIN.*PRIVATE KEY" . --exclude-dir=.git 2>/dev/null
```

- [ ] No caches or virtual environments

```bash
find . -path ./.git -prune -o \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.ruff_cache' -o -name '.venv' -o -name 'build' -o -name 'dist' -o -name '*.egg-info' \) -print
```

Every command above must print nothing. If one does, delete the files and confirm `.gitignore`
covers the pattern.

- [ ] No secrets committed. `.env` is ignored; only `.env.example` is tracked.

```bash
git status --porcelain --ignored | grep -E '\.env$|\.pem$|\.key$|id_rsa|secrets'
```

- [ ] Search the diff for credentials, API keys, tokens, real internal hostnames and real IP ranges.

```bash
git grep -nEi '(api[_-]?key|secret|password|token|BEGIN [A-Z ]*PRIVATE KEY)' -- ':!*.md' ':!.env.example'
```

Every hit must be a variable name, a documented placeholder or a log field — never a real value.

## 2. All checks pass

- [ ] Byte-compile

```bash
python -m compileall -q src tests
```

- [ ] Lint

```bash
python -m ruff check src tests
```

- [ ] Native build with full warnings

```bash
make build
```

- [ ] Tests

```bash
python -m pytest
```

- [ ] Deployment script syntax

```bash
bash -n scripts/deploy_rpi.sh
```

- [ ] ShellCheck (CI enforces this)

```bash
shellcheck scripts/deploy_rpi.sh
```

- [ ] Wheel and source distribution build

```bash
python -m build
```

- [ ] Post-quantum backends are detected

```bash
ics-pqc-evidence capabilities
```

- [ ] Or all of the above at once

```bash
make check
```

## 3. Required files present

- [ ] `README.md` — overview, alpha status, architecture, install, usage, limitations
- [ ] `LICENSE` — Apache 2.0
- [ ] `SECURITY.md` — authorized-use policy and private vulnerability reporting
- [ ] `CONTRIBUTING.md`
- [ ] `CHANGELOG.md` — updated for this release
- [ ] `CITATION.cff` — renders as "Cite this repository"
- [ ] `.gitignore`, `.env.example`
- [ ] `docs/architecture.md`, `docs/threat-model.md`, `docs/experiments.md`
- [ ] `docs/pqc-evidence-architecture.md`, `docs/pqc-evidence-format.md`,
      `docs/pqc-key-management.md`, `docs/pqc-threat-model.md`,
      `docs/pqc-archive-format.md`, `docs/pqc-benchmarks.md`
- [ ] `scripts/make_release.py`
- [ ] `.github/workflows/ci.yml`
- [ ] `config/controller.example.json` (and **no** tracked `config/controller.json`)
- [ ] `data/pcaps/.gitkeep`, `data/raw/.gitkeep` — the directories exist, their contents do not

## 4. Documentation honesty

- [ ] The README states this is an **alpha research prototype**, not production software.
- [ ] The DNP3 component is described as an interaction sensor, **not** a DNP3 outstation.
- [ ] The SSH component is described as a banner decoy that performs **no key exchange**.
- [ ] The Modbus honeypot is **not** claimed to be standards compliant.
- [ ] Conference talks are described as **presentations**, with no claim of peer review or
      proceedings.
- [ ] Every placeholder URL (`OWNER`) has been replaced with the real one.
- [ ] The PQC layer is described as **not TLS**, not encryption of ICS traffic, not attack
      prevention, and **not** a guarantee of legal chain of custody.
- [ ] It is stated that a compromised node's whole log can still be deleted.
- [ ] Public test fixtures, if any, are labelled public-only.
- [ ] Known limitations are current.

## 5. Safe defaults verified

- [ ] Controller binds `127.0.0.1`

```bash
grep -n 'host: str = "127.0.0.1"' src/ics_deception/controller/config.py
```

- [ ] Native honeypot binds loopback on an unprivileged port

```bash
grep -nE 'bind_addr = "127.0.0.1"|port = 5020' src/native/modbus_honeypot.cpp
```

- [ ] Random error injection defaults to zero

```bash
grep -n 'error_percent = 0' src/native/modbus_honeypot.cpp
```

- [ ] No component autostarts, and none is enabled by default

```bash
grep -c '"enabled": false' config/controller.example.json
```

- [ ] Credential capture is off by default

```bash
grep -n 'capture_credentials = false' src/native/common/decoy.h
```

- [ ] Evidence signing is disabled by default

```bash
grep -n 'ICS_PQC_EVIDENCE_MODE=disabled' .env.example
```

- [ ] No classical signature fallback exists

```bash
grep -rniE '\b(RSA|ECDSA|Ed25519)\b' src/ics_deception/pqc_evidence/*.py | grep -v 'never\|not \|no fallback\|refus\|reject'
```

The command above must print nothing: every mention of a classical algorithm should be a statement
that it is *not* used.

- [ ] The test-only backend cannot be selected implicitly

```bash
grep -n 'never auto-selected\|allow_test_backend' src/ics_deception/pqc_evidence/crypto_backend.py | head -3
```

- [ ] Evidence ordering and crash safety hold

```bash
python -m pytest tests/pqc_evidence/test_failure_recovery.py tests/pqc_evidence/test_signer.py -q
```

These cover the properties the release depends on: file order equals sequence order under concurrent
writers, a sequence is issued at most once, and a crash at any transaction stage leaves a consistent
chain.

- [ ] Text files use LF, so the deployment script runs on Linux

```bash
python -m pytest tests/test_release_hygiene.py -q
```

## 6. Release artifact

- [ ] Build the portable release ZIP

```bash
python scripts/make_release.py --output dist/release
```

The script fails if any forbidden file type, directory or private key reaches the archive, and
independently re-opens the finished ZIP to verify it.

- [ ] Every ZIP entry uses forward slashes, not backslashes

```bash
python -c "import zipfile,glob,sys; [sys.exit(f'backslash in {n}') for z in glob.glob('dist/release/*.zip') for n in zipfile.ZipFile(z).namelist() if chr(92) in n]; print('paths portable')"
```

- [ ] `scripts/deploy_rpi.sh` kept its executable bit

```bash
python -c "import zipfile,glob; [print(i.filename, oct((i.external_attr>>16)&0o777)) for z in glob.glob('dist/release/*.zip') for i in zipfile.ZipFile(z).infolist() if i.filename.endswith('deploy_rpi.sh')]"
```

- [ ] Checksums verify

```bash
cd dist/release && sha256sum -c SHA256SUMS
```

## 7. Repository settings after the first push

- [ ] Description and topics set (`ics`, `scada`, `honeypot`, `deception`, `modbus`, `dnp3`).
- [ ] **Private vulnerability reporting** enabled (Settings → Security).
- [ ] Branch protection on `main`: require the CI check, require a pull request.
- [ ] Actions permissions set to read-only by default.
- [ ] Dependabot alerts and security updates enabled.
- [ ] Confirm the CI badge and workflow run green on the first push.
- [ ] Tag the release and verify the "Cite this repository" button renders `CITATION.cff`.

## 8. Final sanity pass

```bash
git status --porcelain
```

```bash
git ls-files | wc -l
```

- [ ] Working tree clean, and the tracked file count matches what you expect.
- [ ] `git ls-files` contains no path under `build/`, `runtime/`, `keys/`, `archives/` or `.venv/`.
- [ ] One last look for key material in the diff you are about to push:

```bash
git diff --cached | grep -E "BEGIN.*PRIVATE KEY|INSECURE-TEST-ONLY" || echo "clean"
```
