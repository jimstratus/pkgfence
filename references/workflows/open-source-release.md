# Open-source release workflow

Use this workflow when preparing a public `pkgfence` release from a private working repository.

## Default recommendation

**Prefer a fresh-history public repository.** It is the safest and simplest path because it avoids publishing old commits that may still contain private material.

Do **not** sanitize the existing private repository in place if your goal is to keep sensitive history out of the public record.

## Option A — fresh-history public repo (recommended)

1. Keep the existing repository private.
2. Create a separate public repository for the open-source release.
3. In a clean working directory, copy only the files that are meant to be public.
4. Review the copied tree before the first commit:
   - source code
   - tests and fixtures
   - docs, screenshots, and release notes
   - example configs and sample data
5. Remove or rewrite anything private before creating the first public commit:
   - secrets, tokens, keys, passwords
   - private hostnames, usernames, internal URLs, issue links
   - sensitive examples, screenshots, customer names, or operator notes
6. Initialize the public repo with fresh history and commit only the curated tree.
7. Verify the new repo again before publishing.

This path avoids carrying over the original git history at all.

## Option B — preserve history by rewriting a clone

Only use this path if keeping commit history matters.

1. Make a local clone or copy of the private repository.
2. Rewrite that copy's history to remove sensitive material from **all** commits.
3. Review rewritten history for:
   - files and file contents
   - commit messages
   - tags and release notes
4. Publish only the rewritten copy.
5. Keep the original repository private.

Rewriting history is riskier because a missed file, message, or tag can still leak private information.

## Secrets handling

Treat any secret that may have been committed or shared as compromised.

- Rotate tokens, passwords, keys, and credentials even if you scrub them from git history.
- Replace sensitive examples with dummy values before publishing.
- Avoid copying local runtime state into the public repo. In `pkgfence`, the gitignored `state/` tree is especially sensitive because it may contain hostnames, reports, exceptions, and other operational data.

## Pre-publish verification checklist

Before publishing the public repo, confirm that it does **not** contain:

- secrets in tracked files
- secrets or private details in commit messages
- private URLs, hostnames, usernames, or infrastructure identifiers
- sensitive screenshots, fixtures, examples, reports, or release notes
- generated state or local operator data

Use both manual review and secret-scanning tools before the first public push.

## Practical guidance for pkgfence

- Start from the public-facing source, tests, and docs that are intended to ship.
- Re-review `planning/`, `references/`, and any historical artifacts before copying them into a public repo.
- Keep `.gitignore` protections for runtime state in place, but do not rely on `.gitignore` alone to sanitize an already-private history.

## Bottom line

- **Best safety:** separate public repo + curated copy + fresh history
- **Higher risk:** rewritten clone with preserved history

If there is any doubt, choose the fresh-history path.
