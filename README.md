# Nexora VulnScan

A training/demo security assessment dashboard. The Vercel deployment serves the static frontend. The FastAPI/Nmap backend runs as a separate Docker web service.

## Deploy the frontend to Vercel

1. Import this GitHub repository into Vercel.
2. Use the repository root as the project root.
3. Use the static/no-framework preset, with no build command and no output directory.
4. Deploy. The landing page is `/`; the dashboard is `/dashboard.html`.

The root contains no Python entry point, so Vercel deploys only the static site. `backend/` is built separately by Render.

## Deploy the Nmap backend to Render

1. In Render, create a Blueprint from this repository and select `render.yaml`.
2. Keep the service on the Free plan for a demo. The free service sleeps when idle and its filesystem is temporary; scan history can be lost when it restarts or sleeps.
3. When prompted for `FRONTEND_ORIGINS`, enter the exact deployed Vercel origin, for example `https://your-project.vercel.app` (no trailing slash).
4. When prompted for `ALLOWED_TARGETS`, enter only the exact IPv4 address of a system you own or have written authorization to assess. Do not use a university or third-party target without explicit permission.
5. Render generates `SCAN_API_KEY`. Keep it private. Do not add it to GitHub or Vercel environment variables for this static frontend.
6. After deployment, copy the backend's HTTPS service URL and open the Vercel dashboard. Open Settings (gear), enter the backend URL and the API key, test the connection, then save.

The backend rejects scans until its allowlist is configured. It only runs a fixed, bounded TCP connect/service scan; it does not exploit targets. The target must be reachable from the backend host.

## Notes

- The API key is entered in the browser session only. Anyone who can use that browser session can submit scans, so only enter it on your own trusted device.
- Render's free filesystem is ephemeral. Reports are stored there for the demo and may disappear after service sleep/restart/redeploy. Persistent retention requires a persistent disk or external database.
- This is a coursework/demo setup, not a hardened multi-user production scanner. Do not put shared credentials in frontend source.
