/**
 * zkFetch Sidecar — lightweight HTTP service that wraps Reclaim Protocol's zkFetch.
 *
 * The Rust daemon calls this when it needs a zero-knowledge proof that Signal's
 * server delivered specific message bytes (for SKDM attestation).
 *
 * Endpoints:
 *   POST /zkfetch — execute a zkFetch request, return the proof
 *   GET  /health  — liveness check
 *
 * Env vars:
 *   RECLAIM_APP_ID     — Reclaim application ID (0x...)
 *   RECLAIM_APP_SECRET — Reclaim application secret (0x...)
 *   ZKFETCH_PORT       — listen port (default 7585)
 */

const http = require('http');
const { ReclaimClient } = require('@reclaimprotocol/zk-fetch');

const APP_ID = process.env.RECLAIM_APP_ID;
const APP_SECRET = process.env.RECLAIM_APP_SECRET;
const PORT = parseInt(process.env.ZKFETCH_PORT || '7585', 10);

if (!APP_ID || !APP_SECRET) {
  console.error('RECLAIM_APP_ID and RECLAIM_APP_SECRET must be set');
  process.exit(1);
}

const client = new ReclaimClient(APP_ID, APP_SECRET, true);

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  if (req.method === 'POST' && req.url === '/zkfetch') {
    let body = '';
    for await (const chunk of req) {
      body += chunk;
    }

    try {
      const request = JSON.parse(body);
      const { url, publicOptions, privateOptions } = request;

      if (!url) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'url is required' }));
        return;
      }

      console.log(`zkFetch: ${url}`);

      const proof = await client.zkFetch(
        url,
        publicOptions || { method: 'GET' },
        privateOptions || {},
        2,   // retries
        2000 // retry interval ms
      );

      console.log(`zkFetch: proof generated`);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ proof }));
    } catch (err) {
      console.error('zkFetch error:', err.message || err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message || 'zkFetch failed' }));
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`zkFetch sidecar listening on 127.0.0.1:${PORT}`);
});
