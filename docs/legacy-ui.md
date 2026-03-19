# Legacy UI — Deprecated

The original web/ micro-frontend (MFE) architecture has been **deprecated** and replaced by `suite-ui/aldeci`, a unified Vite + React application.

## Migration

All legacy MFEs have been moved to `archive/web_mfe_legacy/` for reference.

The new official UI is at `suite-ui/aldeci/` and connects to the FastAPI backend on port 8000.

## Why

- Consolidated 4 separate MFEs into one unified app
- Migrated from Create React App to Vite for faster builds
- Single `.env.example` with `VITE_API_URL` for backend connection
- Screen-to-API mapping documented in `suite-ui/aldeci/SCREEN_API_MAPPING.md`

## Running the UI

```bash
cd suite-ui/aldeci
npm install
npm run dev   # starts on http://localhost:5173
```
