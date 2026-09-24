const express = require('express');
const {
  validateDestinationUrl,
  generateShortCode,
  maskClientIp
} = require('../security/sanitizer');

const router = express.Router();
const urlStore = new Map();

urlStore.set('owasp26', {
  code: 'owasp26',
  targetUrl: 'https://owasp.org/www-community/Source_Code_Analysis_Tools',
  host: 'owasp.org',
  createdAt: new Date().toISOString(),
  visits: 1
});

router.get('/api/links', (_req, res) => {
  const items = Array.from(urlStore.values());
  res.json({ total: items.length, links: items });
});

router.post('/api/links', (req, res) => {
  const { url } = req.body || {};
  const check = validateDestinationUrl(url);

  if (!check.valid) {
    return res.status(400).json({ error: check.reason });
  }

  const code = generateShortCode();
  const record = {
    code,
    targetUrl: check.normalizedUrl,
    host: check.host,
    createdAt: new Date().toISOString(),
    visits: 0,
    creatorHash: maskClientIp(req.ip)
  };

  urlStore.set(code, record);
  return res.status(201).json(record);
});

router.get('/r/:code', (req, res) => {
  const code = String(req.params.code || '').replace(/[^a-zA-Z0-9]/g, '');
  const entry = urlStore.get(code);

  if (!entry) {
    return res.status(404).json({ error: 'Short code not found.' });
  }

  const check = validateDestinationUrl(entry.targetUrl);
  if (!check.valid) {
    return res.status(400).json({ error: 'Destination blocked by security policy.' });
  }

  entry.visits += 1;
  return res.redirect(302, check.normalizedUrl);
});

module.exports = { router, urlStore };
