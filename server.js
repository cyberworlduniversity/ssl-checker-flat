const express = require('express');
const https = require('https');
const dns = require('node:dns').promises;
const net = require('node:net');
const path = require('path');

const app = express();
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Block non-public destinations so this public endpoint cannot be used to
// probe loopback, private, link-local, metadata, or other special-use networks.
const BLOCKED_IPV4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function ipv4Number(address) {
  return address.split('.').reduce((value, part) => ((value << 8) | Number(part)) >>> 0, 0);
}

function isPublicAddress(address) {
  // This checker currently supports public IPv4 destinations only. IPv6 is
  // rejected until equivalent IPv6 range validation is implemented.
  if (net.isIP(address) !== 4) return false;
  const value = ipv4Number(address);
  return !BLOCKED_IPV4.some(([subnet, prefix]) => {
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return (value & mask) === (ipv4Number(subnet) & mask);
  });
}

function normalizeHostname(input) {
  if (typeof input !== 'string' || input.trim().length === 0 || input.length > 2048) {
    throw new Error('Enter a valid hostname or URL.');
  }
  let parsed;
  try {
    parsed = new URL(input.trim().includes('://') ? input.trim() : `https://${input.trim()}`);
  } catch {
    throw new Error('Enter a valid hostname or URL.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error('Only HTTP/HTTPS hostnames without credentials are supported.');
  }
  if (parsed.port && parsed.port !== '443' && parsed.port !== '80') {
    throw new Error('Custom ports are not supported.');
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname.length > 253) throw new Error('Invalid hostname.');
  return hostname;
}

async function resolvePublicHost(hostname) {
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error('The hostname resolves to a non-public or unsupported address.');
  }
  return addresses;
}

function checkSSL(hostname) {
  return new Promise(async (resolve, reject) => {
    try {
      // Resolve once, reject private/special-use IPs, then pin the TLS lookup
      // to those vetted addresses to reduce DNS-rebinding/SSRF risk.
      const addresses = await resolvePublicHost(hostname);
      const pinned = addresses[0];
      const lookup = (host, options, callback) => {
        if (options && options.all) return callback(null, addresses);
        callback(null, pinned.address, pinned.family);
      };

      const options = {
        hostname,
        port: 443,
        path: '/',
        method: 'HEAD',
        lookup,
        // Intentionally false only so expired/invalid certificates can be
        // inspected; the result reports validity and must not be treated as trusted.
        rejectUnauthorized: false,
        servername: net.isIP(hostname) ? undefined : hostname,
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate(true);
        if (!cert || Object.keys(cert).length === 0) {
          res.resume();
          return reject(new Error('No certificate found'));
        }

        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isValid = Number.isFinite(validFrom.getTime()) &&
          Number.isFinite(validTo.getTime()) && now >= validFrom && now <= validTo;
        const cipher = res.socket.getCipher();

        let score = 0;
        if (isValid) score += 40;
        if (daysUntilExpiry > 30) score += 20;
        if (daysUntilExpiry > 90) score += 10;
        if (cipher && cipher.name && cipher.name.includes('TLS')) score += 15;
        if (cipher && cipher.version && cipher.version.includes('TLSv1.3')) score += 15;
        else if (cipher && cipher.version && cipher.version.includes('TLSv1.2')) score += 10;
        if (cert.subjectaltname) score += 10;

        res.resume();
        resolve({
          hostname,
          subject: { CN: cert.subject?.CN || hostname, O: cert.subject?.O || 'Unknown', C: cert.subject?.C || 'Unknown' },
          issuer: { CN: cert.issuer?.CN || 'Unknown', O: cert.issuer?.O || 'Unknown', C: cert.issuer?.C || 'Unknown' },
          validFrom: Number.isFinite(validFrom.getTime()) ? validFrom.toISOString() : null,
          validTo: Number.isFinite(validTo.getTime()) ? validTo.toISOString() : null,
          daysUntilExpiry,
          isValid,
          serialNumber: cert.serialNumber || 'N/A',
          fingerprint: cert.fingerprint || 'N/A',
          cipher: cipher?.name || 'Unknown',
          protocol: cipher?.version || 'Unknown',
          subjectAltNames: cert.subjectaltname ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '')) : [],
          securityScore: Math.min(score, 100),
          certificateTrustedByNode: res.socket.authorized,
        });
      });

      req.on('error', reject);
      req.setTimeout(10000, () => req.destroy(new Error('Connection timed out')));
      req.end();
    } catch (error) {
      reject(error);
    }
  });
}

app.get('/api/check', async (req, res) => {
  let hostname;
  try {
    hostname = normalizeHostname(req.query.url);
    const result = await checkSSL(hostname);
    res.json(result);
  } catch (err) {
    const clientError = /valid hostname|credentials|Custom ports|non-public|unsupported address/i.test(err.message);
    res.status(clientError ? 400 : 502).json({ error: err.message || 'Failed to check SSL certificate' });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3001;
if (require.main === module) {
  app.listen(PORT, () => console.log(`SSL Checker running on http://localhost:${PORT}`));
}

module.exports = { app, normalizeHostname, isPublicAddress, resolvePublicHost, checkSSL };
