# Repository workflow

Owner: Eryk Szczesniak. Git identity must be:
- user.name: erykszczesniak
- user.email: eryks453@gmail.com

## Branches and review

- main is the only long-lived integration branch.
- Before starting a feature, update main with git pull --ff-only.
- Implement each feature on feature/<short-kebab-case>.
- Use small, imperative, English Conventional Commits.
- Open one pull request per feature. Aim for no more than about 400 changed lines; split larger features into dependent, reviewable pull requests.
- Keep each intermediate change buildable. Move tests with the behavior they verify.
- For stacked changes, integrate bottom-up and rebase the next branch onto the updated main.
- Eryk explicitly approves pull requests before merge. Implementation or permission to push is not approval to merge.
- Squash merge only. The exact merge subject is:
  Merge pull request #<PR_NUMBER> from erykszczesniak/<branch-name>
- Preserve feature branches. Do not delete branches during or after merge.
- Confirm gh is authenticated as erykszczesniak before publishing.
- Do not push feature implementation directly to main.
- Do not rewrite published history without explicit authorization.
- Never invent prior reviews, approvals, CI results or implementation dates.

## Content and quality

- Git artifacts, documentation, UI and API text are in English.
- Use normal hyphens, not em dashes.
- Do not add co-author trailers or development-tool attribution.
- Keep credentials and private configuration out of Git.
- Each feature includes relevant tests, clear WHAT/WHY and verification results.
- Run the repository quality gates and inspect remote CI before calling a pull request ready.
- A billing or infrastructure block is not a passing CI result.
- Keep MVP and Extended features separate; Extended must not block a working MVP.

## Backend gates

Use Python 3.12 and uv. Run ruff, black --check, mypy app and pytest. Verify Alembic consistency and Docker Compose startup. Exercise PostgreSQL integration where available. Changes to API schemas must update docs/API-CONTRACT.md. Separate MVP incident/analysis/postmortem features from Extended integrations, search, async jobs and deployment features.
