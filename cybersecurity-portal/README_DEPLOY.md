# 🚀 Deployment Guide: SecureEye Portal

This guide explains how to deploy the SecureEye Portal for free using **Render.com** (Backend) and **Vercel** (Frontend).

## 1. Prerequisites
- A **GitHub** account.
- The project pushed to a GitHub repository.

## 2. Backend Deployment (Render.com)
1. Go to [Render.com](https://render.com) and create a **New Web Service**.
2. Connect your GitHub repository.
3. Select the **`backend`** folder as the Root Directory.
4. **Settings:**
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. **Environment Variables:**
   - `DATABASE_URL`: (Paste your Neon.tech Postgres URL or leave blank for temporary SQLite)
   - `ALLOWED_ORIGINS`: `*` (Or your Vercel URL after deployment)
   - `PUBLIC_BACKEND_URL`: Your Render backend URL, e.g. `https://secureeye-api.onrender.com`
   - `KEEP_ALIVE_INTERVAL_SECONDS`: `240`
   - `GEMINI_API_KEY`: `AQ.Ab8RN6K5xbM_CwtdVSv9A4ZCVClSF6k-SDZueZLXMGmB3JTAVw`
   - `SECRET_KEY`: (A random string)

## 3. Frontend Deployment (Vercel)
1. Go to [Vercel.com](https://vercel.com) and click **Add New Project**.
2. Connect your GitHub repository.
3. Select the **`frontend`** folder.
4. **Framework Preset:** `Vite` (Detected automatically).
5. **Environment Variables:**
   - `VITE_API_URL`: (Paste your **Render.com** URL followed by `/api`, e.g., `https://secureeye-api.onrender.com/api`)
6. Click **Deploy**.

## 4. Live Updates
Whenever you push changes to your GitHub repository, both Render and Vercel will automatically redeploy your website with the latest code!

## 5. Keep the Backend Warm
The frontend now wakes the backend before login and sends a small `/api/health` pulse while the site is open. The backend also runs its own keep-alive pulse when `PUBLIC_BACKEND_URL` is set.

For Render free services, an external uptime monitor is still recommended because a sleeping server cannot run its own timer. Add a monitor that calls:

`https://your-render-service.onrender.com/api/health`

Use a 5-minute interval.
