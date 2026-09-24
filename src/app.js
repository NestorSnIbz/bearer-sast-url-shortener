const express = require('express');
const helmet = require('helmet');
const { router: linksRouter, urlStore } = require('./routes/links');

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    scanner: 'Bearer CLI (OWASP SAST)',
    totalLinks: urlStore.size
  });
});

app.get('/', (_req, res) => {
  const rows = Array.from(urlStore.values())
    .map(
      (item) => `
      <tr>
        <td><code>${item.code}</code></td>
        <td><a href="/r/${item.code}" target="_blank" rel="noopener noreferrer">${item.targetUrl}</a></td>
        <td>${item.host}</td>
        <td>${item.visits}</td>
      </tr>`
    )
    .join('');

  res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SafeLink - SAST Audit with Bearer CLI</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 880px; margin: 40px auto; padding: 0 20px; background: #f8fafc; color: #0f172a; }
    header { background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 10px; margin-bottom: 24px; }
    h1 { margin: 0 0 8px 0; font-size: 24px; }
    .badge { display: inline-block; background: #0284c7; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 13px; }
    .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; margin-bottom: 24px; }
    input[type="url"] { width: 72%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; }
    button { padding: 10px 18px; background: #0284c7; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #e2e8f0; padding: 10px; text-align: left; font-size: 14px; }
    th { background: #f1f5f9; }
    code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <header>
    <h1>SafeLink: URL Shortener Audited with Bearer CLI</h1>
    <span class="badge">OWASP Source Code Analysis Tools | SAST & Data Flow</span>
  </header>
  <div class="card">
    <h2>Shorten a URL</h2>
    <form id="shortForm">
      <input type="url" id="urlInput" placeholder="https://owasp.org" required />
      <button type="submit">Shorten URL</button>
    </form>
    <p id="feedback"></p>
  </div>
  <div class="card">
    <h2>Registered Links</h2>
    <table>
      <thead>
        <tr><th>Code</th><th>Target URL</th><th>Host</th><th>Visits</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
  <script>
    document.getElementById('shortForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = document.getElementById('urlInput').value;
      const res = await fetch('/api/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (res.ok) {
        window.location.reload();
      } else {
        const err = await res.json();
        document.getElementById('feedback').textContent = err.error || 'Failed to register URL';
      }
    });
  </script>
</body>
</html>`);
});

app.use(linksRouter);

module.exports = app;
