const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const app = require('../src/app');

function makeRequest(server, path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: addr.port,
        path,
        method,
        headers: payload
          ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(payload)
            }
          : {}
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          resolve({ statusCode: res.statusCode, headers: res.headers, body: raw });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('GET /health returns status ok and Helmet security headers', async () => {
  const server = app.listen(0);
  try {
    const res = await makeRequest(server, '/health');
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    const data = JSON.parse(res.body);
    assert.equal(data.status, 'ok');
  } finally {
    server.close();
  }
});

test('POST /api/links rejects javascript: schemes to prevent XSS and Open Redirect', async () => {
  const server = app.listen(0);
  try {
    const res = await makeRequest(server, '/api/links', 'POST', {
      url: 'javascript:alert(1)'
    });
    assert.equal(res.statusCode, 400);
    const data = JSON.parse(res.body);
    assert.match(data.error, /Only HTTP and HTTPS protocols are allowed/);
  } finally {
    server.close();
  }
});

test('POST /api/links registers a valid HTTPS URL and returns a 302 redirect', async () => {
  const server = app.listen(0);
  try {
    const createRes = await makeRequest(server, '/api/links', 'POST', {
      url: 'https://www.nist.gov/itl/csd/secure-systems-and-applications/source-code-security-analyzers'
    });
    assert.equal(createRes.statusCode, 201);
    const created = JSON.parse(createRes.body);
    assert.ok(created.code);

    const redirectRes = await makeRequest(server, `/r/${created.code}`, 'GET');
    assert.equal(redirectRes.statusCode, 302);
    assert.equal(
      redirectRes.headers.location,
      'https://www.nist.gov/itl/csd/secure-systems-and-applications/source-code-security-analyzers'
    );
  } finally {
    server.close();
  }
});
