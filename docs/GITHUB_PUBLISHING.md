# GitHub publishing checklist

## Before the first commit

- [ ] Confirm `.env` is ignored: `git check-ignore -v .env`.
- [ ] Search staged files for secrets; never print the key itself.
- [ ] Confirm `data/cve_combined.csv`, `data/uploads/`, `chroma_db/`,
      `frontend/node_modules/`, and `.next/` are ignored.
- [ ] Keep the processed CVE subset, source manifest, screenshots, and measured
      reports in the repository.
- [ ] Review third-party source terms and attribution in `doc/SOURCES.md`.
- [ ] Run backend tests, frontend lint/build, and `docker compose config --quiet`.
- [ ] Open the application and verify the README screenshot still matches it.

## Suggested repository metadata

- Repository name: `secureops-ics-rag`
- Description: `Full-stack RAG assistant for OT/ICS cybersecurity using CISA, NIST, and MITRE knowledge sources.`
- Topics: `rag`, `llm`, `ics-security`, `ot-security`, `fastapi`, `nextjs`,
  `chromadb`, `hybrid-search`, `mitre-attack`, `docker`
- Visibility: public for portfolio use, after the secret scan passes.
- Default branch: `main`

## Local Git commands

```powershell
git init -b main
git add .
git status --short
git diff --cached --stat
git commit -m "feat: publish SecureOps full-stack ICS RAG assistant"
```

Inspect the staged file list before committing. If a sensitive file appears,
remove it from the index and fix `.gitignore` before proceeding.

## Create and push the remote

After creating an empty public repository named `secureops-ics-rag` in the
GitHub web interface:

```powershell
git remote add origin https://github.com/xianzaren/secureops-ics-rag.git
git push -u origin main
```

Then enable GitHub private vulnerability reporting, verify the Actions workflow,
add the suggested topics, and pin the repository on your profile.

## Recommended first release

Create tag `v1.0.0` only after CI passes from a clean clone and the Docker quick
start has been tested. Attach no `.env`, raw dataset, model cache, vector index,
or user-uploaded document to the release.
