# ShieldAI Deployment Guide

## Quick Deployment to Render.com (FREE)

### Prerequisites

- GitHub account
- Render.com account (free)
- Project pushed to a GitHub repository

### Step 1: Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ShieldAI.git
git push -u origin main
```

### Step 2: Deploy on Render

1. Go to [Render](https://render.com)
2. Sign up / login with GitHub
3. Click **"New +" → "Web Service"**
4. Connect your ShieldAI repository
5. Configure:
   - **Name**: `shieldai`
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free
6. Click **Create Web Service**

### Step 3: Add Environment Variables

In Render dashboard → your service → **Environment** tab, add:

```env
RENDER=true
DATABASE_PATH=:memory:
MAX_PROMPT_LENGTH=10000
RATE_LIMIT=100
DEBUG=False
```

Optional (if using Google APIs for enhanced semantic analysis):

```env
GOOGLE_API_KEY=your-google-api-key-here
GOOGLE_OAUTH_CLIENT_ID=your-google-oauth-client-id-here
```

You should also set:

```env
AUTH_SECRET_KEY=change-me-to-a-long-random-secret
```

### Step 4: Access Your App

After Render finishes building and deploying, your app will be live at:

```text
https://shieldai-xxxx.onrender.com
```

## Configuration

- All configuration is driven by environment variables.
- Local development can use a `.env` file (see `.env.example`).
- On Render, **do not** commit `.env`; configure values in the dashboard.

## Monitoring

- **Logs**: Render dashboard → Logs tab
- **Metrics**: Render dashboard → Metrics tab
- **Errors**: Check logs for stack traces or initialization errors

## Updating Deployment

To deploy new changes:

```bash
git add .
git commit -m "Update ShieldAI"
git push
```

Render automatically re-builds and redeploys the latest commit on `main`.

## Troubleshooting

### Build Fails

- Check Render build logs for specific errors
- Verify `requirements.txt` installs successfully locally
- Try **"Clear build cache & deploy"** from the Render dashboard

### App Crashes on Start

- Confirm `PORT` is passed from environment (Render sets `$PORT`)
- Ensure `RENDER=true` is configured so `config.py` and the database use the correct mode
- Check that `AUTH_SECRET_KEY` and any API keys are valid

### Database Issues

- On free Render, the file system is effectively ephemeral
- This project is configured to use **`:memory:`** SQLite when `RENDER=true`
- That means attack history disappears on restart (suitable for demos, not long-term storage)

## Free Tier Limitations

- App may sleep after inactivity; first request after sleep can take ~30 seconds
- CPU and memory are limited; avoid heavy background jobs

## Support

For issues, check:

1. Render logs
2. This repository's issues
3. `README.md` and this `DEPLOYMENT.md`

