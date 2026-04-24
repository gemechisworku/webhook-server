const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Webhook } = require('svix');
require('dotenv').config();

const app = express();

function getRequestMeta(req) {
  return {
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    contentType: req.headers['content-type']
  };
}

function logWebhook(label, details) {
  console.log(`[${label}] ${JSON.stringify(details, null, 2)}`);
}

// Basic request/response logging for all incoming calls
app.use((req, res, next) => {
  const startedAt = Date.now();
  const reqMeta = getRequestMeta(req);
  logWebhook('HTTP_IN', reqMeta);

  res.on('finish', () => {
    logWebhook('HTTP_OUT', {
      ...reqMeta,
      statusCode: res.statusCode,
      durationMs: Date.now() - startedAt
    });
  });

  next();
});

// Africa's Talking uses urlencoded format
app.use('/webhooks/africastalking', bodyParser.urlencoded({ extended: false }));

// Resend and Cal.com require the raw body for signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// 1. Resend Webhook
app.post('/webhooks/resend', (req, res) => {
  const secret = process.env.RESEND_WEBHOOK_SECRET;
  const headers = req.headers;
  const payload = req.rawBody.toString();
  const receivedAt = new Date().toISOString();

  try {
    const wh = new Webhook(secret);
    const evt = wh.verify(payload, headers);
    logWebhook('RESEND_VERIFIED', {
      receivedAt,
      eventType: evt.type,
      messageId: evt.data?.message_id,
      emailId: evt.data?.email_id,
      from: evt.data?.from,
      to: evt.data?.to,
      subject: evt.data?.subject,
      createdAt: evt.created_at || evt.data?.created_at
    });
    res.status(200).send('Verified');
  } catch (err) {
    logWebhook('RESEND_VERIFY_FAILED', {
      receivedAt,
      error: err.message,
      hasSignatureHeaders: Boolean(headers['svix-id'] && headers['svix-signature'] && headers['svix-timestamp']),
      rawPayloadPreview: payload.slice(0, 300)
    });
    res.status(400).send('Verification failed');
  }
});

const handleCalWebhook = (req, res) => {
  const secret = process.env.CAL_WEBHOOK_SECRET;
  const signatureHeader = req.headers['x-cal-signature-256'];
  const receivedAt = new Date().toISOString();

  if (!secret) {
    logWebhook('CAL_CONFIG_ERROR', {
      receivedAt,
      error: 'Missing CAL_WEBHOOK_SECRET'
    });
    return res.status(500).send('Missing CAL_WEBHOOK_SECRET');
  }

  if (!signatureHeader) {
    logWebhook('CAL_VERIFY_FAILED', {
      receivedAt,
      error: 'Missing x-cal-signature-256 header',
      triggerEvent: req.body?.triggerEvent
    });
    return res.status(400).send('Missing x-cal-signature-256 header');
  }

  const rawPayload = req.rawBody || Buffer.from(JSON.stringify(req.body));
  const hmac = crypto.createHmac('sha256', secret);
  const expectedDigest = hmac.update(rawPayload).digest('hex');
  const providedDigest = String(signatureHeader).replace(/^sha256=/i, '').trim();

  if (providedDigest.length !== expectedDigest.length) {
    logWebhook('CAL_VERIFY_FAILED', {
      receivedAt,
      error: 'Signature length mismatch',
      providedDigestLength: providedDigest.length,
      expectedDigestLength: expectedDigest.length,
      triggerEvent: req.body?.triggerEvent
    });
    return res.status(401).send('Unauthorized');
  }

  const isValid = crypto.timingSafeEqual(
    Buffer.from(providedDigest, 'utf8'),
    Buffer.from(expectedDigest, 'utf8')
  );

  if (isValid) {
    logWebhook('CAL_VERIFIED', {
      receivedAt,
      triggerEvent: req.body?.triggerEvent,
      eventType: req.body?.payload?.type,
      title: req.body?.payload?.title,
      startTime: req.body?.payload?.startTime || req.body?.startTime,
      endTime: req.body?.payload?.endTime || req.body?.endTime,
      bookingUid: req.body?.payload?.uid || req.body?.uid,
      organizerEmail: req.body?.payload?.organizer?.email || req.body?.organizer?.email,
      attendeeEmails: (req.body?.payload?.attendees || req.body?.attendees || []).map((a) => a.email),
      createdAt: req.body?.createdAt
    });
    return res.status(200).send('Verified');
  } else {
    logWebhook('CAL_VERIFY_FAILED', {
      receivedAt,
      error: 'Signature mismatch',
      triggerEvent: req.body?.triggerEvent,
      payloadPreview: rawPayload.toString().slice(0, 300)
    });
    return res.status(401).send('Unauthorized');
  }
};

// 2. Cal.com Webhook
app.post('/webhooks/cal', handleCalWebhook);

// Alias for tools pointed to the base ngrok URL (POST /)
app.post('/', handleCalWebhook);

function firstQueryParam(val) {
  if (val == null) return undefined;
  return Array.isArray(val) ? val[0] : val;
}

// HubSpot MCP inspector completes OAuth with GET /?code=... (and optional ?state=...)
app.get('/', async (req, res) => {
  const oauthError = firstQueryParam(req.query.error);
  if (oauthError) {
    const desc = firstQueryParam(req.query.error_description);
    return res.status(200).type('text/plain').send(`HubSpot OAuth was not completed.\n${oauthError}${desc ? `\n${desc}` : ''}`);
  }

  const code = firstQueryParam(req.query.code);
  if (code) {
    const clientId = process.env.HUBSPOT_CLIENT_ID;
    const clientSecret = process.env.HUBSPOT_CLIENT_SECRET;
    const proto = (req.get('x-forwarded-proto') || req.protocol || 'https').split(',')[0].trim();
    const host = (req.get('x-forwarded-host') || req.get('host') || '').split(',')[0].trim();
    const redirectUri = process.env.HUBSPOT_REDIRECT_URI || `${proto}://${host}/`;

    if (!clientId || !clientSecret) {
      return res.status(200).type('text/plain').send(
        [
          'HubSpot sent an authorization code, but this server cannot exchange it yet.',
          'Set in your environment (e.g. Render env vars):',
          '  HUBSPOT_CLIENT_ID      — from the app Auth / settings page',
          '  HUBSPOT_CLIENT_SECRET  — same secret you use for webhook signatures',
          'Optional:',
          '  HUBSPOT_REDIRECT_URI   — must match the redirect URL registered in HubSpot exactly',
          `  (if omitted, using: ${redirectUri})`,
          '',
          'Webhook endpoint (POST): /webhooks/hubspot'
        ].join('\n')
      );
    }

    try {
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        code: String(code)
      });
      const tokenRes = await fetch('https://api.hubapi.com/oauth/v1/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
      });
      const rawText = await tokenRes.text();
      let data;
      try {
        data = JSON.parse(rawText);
      } catch {
        data = { message: rawText };
      }

      if (!tokenRes.ok) {
        logWebhook('HUBSPOT_OAUTH_TOKEN_FAILED', {
          status: tokenRes.status,
          hubspot: typeof data === 'object' ? data : { message: String(data) }
        });
        return res.status(200).type('text/plain').send(
          [
            `HubSpot token exchange failed (HTTP ${tokenRes.status}).`,
            typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data),
            '',
            'Common fix: set HUBSPOT_REDIRECT_URI to the exact redirect URL configured on your HubSpot app (trailing slash and scheme must match).',
            `Currently using redirect_uri: ${redirectUri}`
          ].join('\n')
        );
      }

      logWebhook('HUBSPOT_OAUTH_TOKEN_OK', {
        expiresIn: data.expires_in,
        tokenType: data.token_type,
        hasRefreshToken: Boolean(data.refresh_token)
      });

      const showTokens = process.env.HUBSPOT_OAUTH_SHOW_TOKENS === '1';
      const lines = [
        'HubSpot OAuth succeeded. Tokens were issued.',
        `expires_in (seconds): ${data.expires_in ?? 'n/a'}`,
        ''
      ];
      if (showTokens) {
        lines.push(
          'HUBSPOT_OAUTH_SHOW_TOKENS=1 is set — remove it after you copy tokens.',
          '',
          `access_token:\n${data.access_token ?? ''}`,
          '',
          `refresh_token:\n${data.refresh_token ?? ''}`
        );
      } else {
        lines.push(
          'Tokens are not shown in the page by default.',
          'Set HUBSPOT_OAUTH_SHOW_TOKENS=1 temporarily to print access_token and refresh_token here, then unset it.',
          'Or read tokens from MCP inspector if it displays them after redirect.'
        );
      }
      lines.push('', 'Webhook endpoint (POST): /webhooks/hubspot');
      return res.status(200).type('text/plain').send(lines.join('\n'));
    } catch (err) {
      logWebhook('HUBSPOT_OAUTH_ERROR', { error: err.message });
      return res.status(500).type('text/plain').send(`OAuth exchange error: ${err.message}`);
    }
  }

  res.status(200).type('text/plain').send(
    [
      'Webhook server is up.',
      '',
      'HubSpot OAuth callback: GET /?code=... (exchange uses HUBSPOT_CLIENT_ID, HUBSPOT_CLIENT_SECRET, optional HUBSPOT_REDIRECT_URI)',
      'HubSpot webhooks (POST): /webhooks/hubspot',
      'Cal.com (POST): /webhooks/cal or POST /',
      'Resend (POST): /webhooks/resend'
    ].join('\n')
  );
});

// --- HubSpot webhook signature helpers (v1 CRM, v2 workflows/cards, v3 OAuth) ---
// https://developers.hubspot.com/docs/api/webhooks/validating-requests

function buildHubSpotRequestUri(req) {
  const proto = (req.get('x-forwarded-proto') || req.protocol || 'https').split(',')[0].trim();
  const host = (req.get('x-forwarded-host') || req.get('host') || '').split(',')[0].trim();
  return `${proto}://${host}${req.originalUrl || ''}`;
}

function decodeHubSpotV3Uri(uri) {
  const replacements = [
    ['%3A', ':'],
    ['%2F', '/'],
    ['%3F', '?'],
    ['%40', '@'],
    ['%21', '!'],
    ['%24', '$'],
    ["%27", "'"],
    ['%28', '('],
    ['%29', ')'],
    ['%2A', '*'],
    ['%2C', ','],
    ['%3B', ';']
  ];
  let out = uri;
  for (const [enc, dec] of replacements) {
    const upper = enc.toUpperCase();
    const lower = enc.toLowerCase();
    out = out.split(upper).join(dec).split(lower).join(dec);
  }
  return out;
}

function timingSafeEqualHexOrAscii(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function verifyHubSpotV1(clientSecret, rawBody, receivedSignature) {
  const source = `${clientSecret}${rawBody}`;
  const expected = crypto.createHash('sha256').update(source, 'utf8').digest('hex');
  return timingSafeEqualHexOrAscii(expected.toLowerCase(), String(receivedSignature).toLowerCase());
}

function verifyHubSpotV2(clientSecret, method, requestUri, rawBody, receivedSignature) {
  const m = String(method).toUpperCase();
  const source = `${clientSecret}${m}${requestUri}${rawBody}`;
  const expected = crypto.createHash('sha256').update(source, 'utf8').digest('hex');
  return timingSafeEqualHexOrAscii(expected.toLowerCase(), String(receivedSignature).toLowerCase());
}

function verifyHubSpotV3(clientSecret, method, requestUri, rawBody, timestampMs, receivedSignature) {
  const ts = Number(timestampMs);
  if (!Number.isFinite(ts)) return false;
  const now = Date.now();
  if (Math.abs(now - ts) > 300000) return false;

  const m = String(method).toUpperCase();
  const uri = decodeHubSpotV3Uri(requestUri);
  const rawString = `${m}${uri}${rawBody}${timestampMs}`;
  const expected = crypto.createHmac('sha256', clientSecret).update(rawString, 'utf8').digest('base64');
  const recv = String(receivedSignature).trim();
  const be = Buffer.from(expected, 'utf8');
  const br = Buffer.from(recv, 'utf8');
  if (be.length !== br.length) return false;
  return crypto.timingSafeEqual(be, br);
}

function verifyHubSpotRequest(req, clientSecret) {
  const rawBody = req.rawBody ? req.rawBody.toString('utf8') : '';
  const requestUri = buildHubSpotRequestUri(req);
  const sigV3 = req.headers['x-hubspot-signature-v3'];
  const tsV3 = req.headers['x-hubspot-request-timestamp'];
  const sig = req.headers['x-hubspot-signature'];
  const sigVersion = (req.headers['x-hubspot-signature-version'] || '').toLowerCase();

  if (sigV3) {
    return verifyHubSpotV3(clientSecret, req.method, requestUri, rawBody, tsV3, sigV3);
  }
  if (sigVersion === 'v2' && sig) {
    return verifyHubSpotV2(clientSecret, req.method, requestUri, rawBody, sig);
  }
  if (sigVersion === 'v1' && sig) {
    return verifyHubSpotV1(clientSecret, rawBody, sig);
  }
  if (sig && !sigVersion) {
    return (
      verifyHubSpotV2(clientSecret, req.method, requestUri, rawBody, sig) ||
      verifyHubSpotV1(clientSecret, rawBody, sig)
    );
  }
  return false;
}

// 4. HubSpot (CRM subscriptions, workflow webhooks, etc.)
app.post('/webhooks/hubspot', (req, res) => {
  const secret = process.env.HUBSPOT_CLIENT_SECRET;
  const receivedAt = new Date().toISOString();

  if (!secret) {
    logWebhook('HUBSPOT_CONFIG_ERROR', {
      receivedAt,
      error: 'Missing HUBSPOT_CLIENT_SECRET'
    });
    return res.status(500).send('Missing HUBSPOT_CLIENT_SECRET');
  }

  const ok = verifyHubSpotRequest(req, secret);
  const body = req.body;

  if (ok) {
    logWebhook('HUBSPOT_VERIFIED', {
      receivedAt,
      signatureVersion: req.headers['x-hubspot-signature-version'] || (req.headers['x-hubspot-signature-v3'] ? 'v3' : undefined),
      eventCount: Array.isArray(body) ? body.length : body != null ? 1 : 0,
      subscriptionTypes: Array.isArray(body)
        ? [...new Set(body.map((e) => e && e.subscriptionType).filter(Boolean))]
        : undefined,
      portalId: Array.isArray(body) ? body[0]?.portalId : body?.portalId
    });
    return res.status(200).send('OK');
  }

  logWebhook('HUBSPOT_VERIFY_FAILED', {
    receivedAt,
    error: 'Signature verification failed',
    hasV3: Boolean(req.headers['x-hubspot-signature-v3']),
    signatureVersion: req.headers['x-hubspot-signature-version'],
    bodyPreview: (req.rawBody ? req.rawBody.toString('utf8') : '').slice(0, 300)
  });
  return res.status(401).send('Unauthorized');
});

// 3. Africa's Talking (SMS/Voice Callback)
app.post('/webhooks/africastalking', (req, res) => {
  // AT sends data as form-urlencoded
  logWebhook('AFRICASTALKING_EVENT', {
    receivedAt: new Date().toISOString(),
    payload: req.body,
    fields: Object.keys(req.body || {})
  });
  
  // For USSD, you MUST return a specific plain text format
  // res.send("CON Welcome to the service \n 1. Balance"); 
  
  res.status(200).send('OK');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
