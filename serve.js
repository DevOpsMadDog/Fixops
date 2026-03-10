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

// 1) Proxy /api/* to Python backend — raw http proxy (no middleware version issues)
app.use('/api', (req, res) => {
  const options = {
    hostname: API_HOST,
    port: API_PORT,
    path: req.originalUrl,
    method: req.method,
    headers: { ...req.headers, host: `${API_HOST}:${API_PORT}` },
  };

  const proxyReq = http.request(options, (proxyRes) => {
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

// 2) Static files
app.use(express.static(distPath));

// 3) SPA fallback
app.use((req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`FixOps ALdeci Production Server on :${PORT}`);
  console.log(`  UI: ${distPath}`);
  console.log(`  API: http://${API_HOST}:${API_PORT}`);
});
