# Webhook server

A small [Express](https://expressjs.com/) service that receives webhooks from several providers, verifies signatures where applicable, logs structured events to the console, and supports a HubSpot OAuth callback for MCP-style flows.

## What it does

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/webhooks/resend` | [Resend](https://resend.com/) email events — verifies with [Svix](https://www.svix.com/) using `RESEND_WEBHOOK_SECRET`; for `email.received`, fetches full content via Resend API when `RESEND_API_KEY` is set. |
| `POST` | `/webhooks/cal` | [Cal.com](https://cal.com/) scheduling webhooks — HMAC SHA-256 via `x-cal-signature-256` and `CAL_WEBHOOK_SECRET`. |
| `POST` | `/` | Same handler as `/webhooks/cal` (convenience when the tool only posts to the root URL). |
| `POST` | `/webhooks/hubspot` | [HubSpot](https://www.hubspot.com/) CRM / workflow style payloads — supports signature v1, v2, and v3 using `HUBSPOT_CLIENT_SECRET`. |
| `POST` | `/webhooks/africastalking` | [Africa’s Talking](https://africastalking.com/) SMS/voice callbacks — `application/x-www-form-urlencoded` body, no signature check in this repo. |
| `GET` | `/` | Health/help text; if opened with `?code=` after HubSpot OAuth, exchanges the code for tokens (see HubSpot section below). |

Every request is logged on the way in and out (`HTTP_IN` / `HTTP_OUT`). Successful verifications log provider-specific labels (for example `RESEND_VERIFIED`, `HUBSPOT_VERIFIED`).

## Prerequisites

- [Node.js](https://nodejs.org/) 18+ (uses global `fetch` for HubSpot OAuth).

## Setup

1. Clone the repository and enter the project directory.

2. Install dependencies:

   ```bash
   npm install
   ```

3. Create a local environment file from the example:

   ```bash
   cp .env.example .env
   ```

4. Edit `.env` and set the secrets you need for the integrations you plan to use. Each variable is documented in [`.env.example`](.env.example) (what it is and where to obtain it in the provider’s UI).

## Run locally

```bash
npm start
```

By default the server listens on port **3000** (or the value of `PORT` in `.env`). You should see:

```text
Server listening on port 3000
```

## How to test locally

### 1. Smoke test (no secrets)

Open or request the root URL:

```bash
curl -s http://localhost:3000/
```

You should get plain text describing the server and endpoints.

### 2. Africa’s Talking (no signing secret)

Simulates a form POST like a delivery report:

```bash
curl -s -X POST http://localhost:3000/webhooks/africastalking \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "phoneNumber=%2B254711XXX&status=Success" -w "\nHTTP %{http_code}\n"
```

Expect **200** and body `OK`. Watch the terminal for `AFRICASTALKING_EVENT`.

### 3. Resend, Cal.com, HubSpot (signature verification)

These routes **require valid signatures** (and the matching env vars). A bare JSON POST will fail verification by design.

- **Resend:** In the Resend dashboard, point a webhook URL to your tunnel (see below) + `/webhooks/resend`, copy the signing secret into `RESEND_WEBHOOK_SECRET`, and set `RESEND_API_KEY` if you want full body/header retrieval for `email.received`.
- **Cal.com:** Configure the webhook secret in Cal and set `CAL_WEBHOOK_SECRET`, then trigger a test booking or Cal’s webhook test UI against `http://localhost:3000/webhooks/cal` (or `/`).
- **HubSpot:** Create a subscription or workflow webhook targeting `https://<your-host>/webhooks/hubspot`, set `HUBSPOT_CLIENT_SECRET`, and trigger a CRM or workflow event.

Important: keep the Resend webhook path as `/webhooks/resend`. Posting Resend events to `/` will hit the Cal.com verifier and fail with Cal signature errors.

To hit **localhost** from the public internet, use a tunnel (for example [ngrok](https://ngrok.com/)):

```bash
ngrok http 3000
```

Use the HTTPS forwarding URL plus the path (for example `https://abc123.ngrok-free.app/webhooks/hubspot`) in the provider’s configuration.

### 4. HubSpot OAuth / MCP (`GET /?code=...`)

When HubSpot redirects the browser to your app with `?code=...`, this server can exchange that code at HubSpot’s **2026-03** token endpoint if you configure:

- `HUBSPOT_CLIENT_ID`
- `HUBSPOT_CLIENT_SECRET`
- `HUBSPOT_CODE_VERIFIER` (PKCE — must match the verifier used for that authorization)
- `HUBSPOT_REDIRECT_URI` (strongly recommended — must match the redirect URL registered on the app exactly)

Optional: `HUBSPOT_OAUTH_SHOW_TOKENS=1` briefly prints tokens in the response for debugging (unset afterward).

See HubSpot’s [remote MCP server](https://developers.hubspot.com/docs/apps/developer-platform/build-apps/integrate-with-the-remote-hubspot-mcp-server) and [OAuth token (2026-03)](https://developers.hubspot.com/docs/api-reference/latest/authentication/manage-oauth-tokens) documentation for details.

## Deploying

Typical platforms (for example [Render](https://render.com/)) set `PORT` automatically. Add the same environment variable names as in `.env.example` in the host’s dashboard; do not commit `.env` to git.

## License

ISC (see [`package.json`](package.json)).
