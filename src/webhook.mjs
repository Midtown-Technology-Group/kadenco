// SPDX-License-Identifier: AGPL-3.0-or-later
import https from 'node:https';
import { lookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';
import { Webhook } from 'standardwebhooks';

export function callbackUrl(raw, allowedHosts) {
  const u = new URL(raw);
  if (u.protocol !== 'https:' || u.port && u.port !== '443' || u.username || u.password
      || u.hash || !allowedHosts.includes(u.hostname)) throw new Error('callback_not_allowed');
  return u;
}

export function signingKey(secret) {
  if (typeof secret !== 'string' || !/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) throw new Error('invalid_signing_key');
  const key = Buffer.from(secret.slice(6), 'base64');
  if (key.length < 24 || key.length > 64 || key.toString('base64') !== secret.slice(6)) throw new Error('invalid_signing_key');
  return secret;
}

export function publicAddress(address) {
  const ip = ipaddr.process(address);
  return ip.range() === 'unicast';
}

// Resolve again on EVERY connection; pin the validated address through TLS lookup.
// No redirects, proxies, private destinations, or unbounded response bodies.
export async function postWebhook(url, headers, body, allowedHosts, resolve = lookup) {
  const u = callbackUrl(url, allowedHosts);
  const addresses = await resolve(u.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(a => !publicAddress(a.address))) throw new Error('callback_address_denied');
  const target = addresses[0];
  return new Promise((accept, reject) => {
    const req = https.request(u, {
      method: 'POST', headers, agent: false, servername: u.hostname,
      lookup: (_host, opts, done) => opts.all ? done(null,[target]) : done(null, target.address, target.family),
      signal: AbortSignal.timeout(10000),
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size > 16384) res.destroy(new Error('callback_response_too_large')); else chunks.push(c); });
      res.on('error', reject);
      res.on('end', () => accept({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', () => reject(new Error('callback_transport_failed')));
    req.end(body);
  });
}

export async function signedPost(subscription, payload, post, now = Date.now()) {
  const body = JSON.stringify(payload);
  if (Buffer.byteLength(body) > 262144) throw new Error('payload_too_large');
  const id = payload.eventId ?? 'verification_'+payload.challenge;
  const at = new Date(now);
  const secrets = [subscription.secret];
  if (subscription.oldSecret && subscription.rotateUntil > now) secrets.push(subscription.oldSecret);
  return post(subscription.url, {
    'content-type': 'application/json', 'webhook-id': id,
    'webhook-timestamp': String(Math.floor(now / 1000)),
    'webhook-signature': secrets.map(s => new Webhook(s).sign(id, at, body)).join(' '),
    'X-MCP-Subscription-Id': subscription.id,
  }, body);
}
