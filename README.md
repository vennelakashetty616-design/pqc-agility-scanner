# Post-quantum migration and crypto-agility scanner

`pqcscan` inventories cryptographic algorithms, libraries, key sizes, certificates, and protocol settings in a source tree. It writes a dependency-aware migration checklist and can compare that inventory in CI.

A scan does not prove that a system is quantum-safe. A clean report is not a quantum-safety attestation.

There was no application codebase to migrate, so this repository contains:

- the scanner
- `samples/legacy-billing`, a synthetic legacy service with outdated crypto on purpose
- a sandbox that swaps classical algorithms through one interface
- a baseline check for newly introduced confirmed findings

The sample is not a secure design and must not be deployed.

## What a run produces

- Confirmed findings, with file and line evidence, for APIs, known dependencies, parsed certificates, and specific protocol tokens
- Uncertain matches, kept in a separate list, for names and comments
- A dependency inventory, including call sites reached through Python, JavaScript, and Go wrappers, and packages that appear only in a lockfile
- A prioritized checklist with a validation gate on each item
- A high-level hybrid classical/post-quantum planning section and the interoperability issues that come with it
- A migration graph: review order, validation gates, and file-to-mechanism edges
- Limitations, compatibility risks, and testing steps

Hybrid options are planning notes. The tool does not implement post-quantum algorithms and will not fill that gap with custom cryptography.

## Run it

Python 3.10 or newer:

```powershell
python -m pip install -e ".[dev]"
python scripts/generate_sample_cert.py
pqcscan scan --path samples/legacy-billing --out reports/sample
pqcscan web --path samples/legacy-billing
pqcscan sandbox --demo
pqcscan ci --path samples/legacy-billing --baseline baselines/legacy-billing.json
python -m pytest
```

`pqcscan web` serves a local dashboard at `http://127.0.0.1:8765`. It scans the `--path` folder when the page opens, and the path box can scan any other project folder on this computer. Each finding shows the file, the line number, and the line of code. The Ask button answers questions from that same scan. `pqcscan scan --out` writes `report.md`, `report.json`, `migration-graph.mmd`, and `dashboard.html` into a folder you choose. Those generated files are not kept in the source tree.

Scan your own tree the same way:

```powershell
pqcscan scan --path C:\path\to\your\repo --out reports\your-repo
pqcscan baseline --path C:\path\to\your\repo --out baselines\your-repo.json
```

Update a baseline only after someone has reviewed the new fingerprints. The CI command exits non-zero when a confirmed library, algorithm, protocol, certificate, or key-size fingerprint appears that is not already listed. Uncertain comment matches do not fail the check. Removed fingerprints are printed and do not fail the check.

## Sandbox

The sandbox is a small `CryptoProvider` interface. These profiles are implemented with the [cryptography](https://cryptography.io/) package, which binds to OpenSSL:

- `aes-256-gcm`
- `ecdsa-p256`
- `ecdsa-p384`
- `rsa-pss-3072`

```powershell
pqcscan sandbox --config examples/sandbox/ecdsa-p256.json
pqcscan sandbox --profile rsa-pss-3072
```

Keys are generated in memory for the demo and are not written to disk. Profile ids for post-quantum algorithms are refused. Point the same interface at a vetted library such as OpenSSL 3.5+ or liboqs when you are ready to experiment outside this process. A successful round-trip only shows that the caller can change classical algorithms by configuration.

## CI

`.github/workflows/crypto-agility.yml` installs the tool, runs the tests, and runs `pqcscan ci` against `samples/legacy-billing`. Copy that step for your own baseline.

## Limits

Static rules miss runtime configuration, HSMs, managed cloud settings, closed-source binaries, and dependencies that are not declared in the tree. Java imports are not followed. Lockfiles are expanded only for package names the scanner knows. Parsed certificates describe those files, not the rest of an estate.
