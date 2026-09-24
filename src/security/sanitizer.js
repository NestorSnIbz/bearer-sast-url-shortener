const crypto = require('crypto');

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

function validateDestinationUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    return { valid: false, reason: 'Destination URL is required.' };
  }

  try {
    const parsed = new URL(rawUrl.trim());
    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      return { valid: false, reason: 'Only HTTP and HTTPS protocols are allowed.' };
    }
    return { valid: true, normalizedUrl: parsed.toString(), host: parsed.hostname };
  } catch {
    return { valid: false, reason: 'Invalid URL format.' };
  }
}

function generateShortCode() {
  return crypto.randomBytes(4).toString('hex');
}

function maskClientIp(ipAddress) {
  if (!ipAddress || typeof ipAddress !== 'string') {
    return '0.0.0.0';
  }
  return crypto.createHash('sha256').update(ipAddress).digest('hex').slice(0, 12);
}

module.exports = {
  validateDestinationUrl,
  generateShortCode,
  maskClientIp
};
