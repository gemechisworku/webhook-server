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
