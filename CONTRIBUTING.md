# Contributing

Thank you for improving SecureOps.

## Development workflow

1. Create a focused branch from `main`.
2. Keep secrets in `.env`; never commit API keys, user uploads, or a local index.
3. Add or update tests for behavior changes.
4. Run the required checks:

   ```powershell
   pytest -q
   Set-Location frontend
   npm ci
   npm run lint
   npm run build
   ```

5. If ingestion or retrieval changes, rebuild the index and regenerate both
   data-quality and evaluation reports.
6. Explain the user-visible behavior, test evidence, and data/provenance impact
   in the pull request.

## Data contributions

- Prefer canonical, machine-readable, versioned sources.
- Record the upstream URL and snapshot/version in `doc/SOURCES.md`.
- Do not add confidential operational documents, credentials, or personal data.
- Keep benchmark questions separate from indexed documents to reduce leakage.

## Commit style

Use short imperative messages, for example:

- `feat: add ATT&CK relationship ingestion`
- `test: enforce multi-source retrieval coverage`
- `docs: publish measured benchmark results`
