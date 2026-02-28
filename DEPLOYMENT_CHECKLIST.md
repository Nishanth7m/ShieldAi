# Deployment Checklist

## Before Pushing to GitHub

- [ ] All files saved
- [ ] `.env` **NOT** committed (present in `.gitignore`)
- [ ] `.env.example` created and up to date
- [ ] `Procfile` created
- [ ] `runtime.txt` created
- [ ] `.gitignore` updated with Python / env / db rules
- [ ] `requirements.txt` complete and installs cleanly
- [ ] Database configuration supports production (`RENDER=true` → `:memory:`)
- [ ] `main.py` uses `PORT` from environment
- [ ] All important paths built with `Path(__file__).resolve()` or config helpers
- [ ] No hardcoded secrets in code
- [ ] Tests pass locally (`scripts/comprehensive_test.py`)

## Deployment Files Present

- [ ] `Procfile`
- [ ] `runtime.txt`
- [ ] `requirements.txt`
- [ ] `.gitignore`
- [ ] `.env.example`
- [ ] `DEPLOYMENT.md`
- [ ] `README.md` (updated)

## After Deployment (Render)

- [ ] App builds successfully
- [ ] App starts without errors (logs show startup banner)
- [ ] Dashboard loads at deployed URL
- [ ] Can analyze **malicious** prompts (BLOCK verdict)
- [ ] Can analyze **benign** prompts (ALLOW verdict)
- [ ] `/docs` (OpenAPI) renders correctly
- [ ] `/api/stats` returns valid JSON
- [ ] `/api/health` reports ONLINE or DEGRADED (not error)
- [ ] Static assets (HTML/JS) load without 404s
- [ ] Login/signup flow works (if enabled)

## Performance Checks

- [ ] `/api/analyze` response time < 200ms for simple prompts (no semantic API)
- [ ] Dashboard initial load < 2 seconds on free tier
- [ ] No obvious memory leaks (memory footprint stable in logs)
- [ ] No repeated error traces in logs

## Final Steps

- [ ] Add live URL to `README.md`
- [ ] Test from at least one mobile device + one laptop
- [ ] Share link for peer testing
- [ ] Monitor logs for 24–48 hours
- [ ] Open issues for any bugs discovered post-deploy

