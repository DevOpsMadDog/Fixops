const express = require('express');
const http = require('http');
const path = require('path');
const url = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse API backend URL from env (supports docker-compose service names)
const backendUrl = process.env.API_BACKEND_URL || 'http://localhost:8000';
const parsed = new url.URL(backendUrl);
const API_HOST = parsed.hostname;
const API_PORT = parseInt(parsed.port, 10) || 8000;

const distPath = path.join(__dirname, 'suite-ui/aldeci-ui-new/dist');

// ── JSON body parser for bridge routes ──
app.use(express.json({ limit: '10mb' }));

// ── 1) API Bridge — serves endpoints Python backend doesn't handle ──
const apiBridge = require('./api-bridge');
app.use(apiBridge);

// ── 2) Proxy /api/* to Python backend for routes it DOES handle ──
app.use('/api', (req, res) => {
  const options = {
    hostname: API_HOST,
    port: API_PORT,
    path: req.originalUrl,
    method: req.method,
    headers: { ...req.headers, host: `${API_HOST}:${API_PORT}` },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    // If Python returns 404, it means Python doesn't know this route either
    // The bridge should have caught it above — but just in case, pass through
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('error', (err) => {
    console.error('API proxy error:', err.message);
    if (!res.headersSent) {
      res.status(502).json({ error: 'API backend unavailable', detail: err.message });
    }
  });

  req.pipe(proxyReq, { end: true });
});

// ── 3) Static files ──
app.use(express.static(distPath));

// ── 4) SPA fallback ──
app.use((req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`╔══════════════════════════════════════════════════╗`);
  console.log(`║  ALdeci FixOps CTEM+ Enterprise Platform         ║`);
  console.log(`║  Production Server Running                       ║`);
  console.log(`╠══════════════════════════════════════════════════╣`);
  console.log(`║  UI:  http://0.0.0.0:${PORT}                         ║`);
  console.log(`║  API: ${backendUrl}                   ║`);
  console.log(`║  Bridge: Active (SQLite-backed endpoints)        ║`);
  console.log(`╚══════════════════════════════════════════════════╝`);
});
