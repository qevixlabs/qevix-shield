# Qevix Shield

> Login protection, two-factor auth, reCAPTCHA, malware scanning, a firewall, and an audit log with alerts. Every protection off until you turn it on.

Qevix Shield is a WordPress security plugin that hardens the parts of WordPress attackers hit first — the login form, XML-RPC, file access, and the URLs that leak information about your install. Everything it blocks is written to a searchable audit log, and critical events can email you automatically.

It installs **neutral**: activating it changes nothing about your site. Every protection stays off until you switch it on, so you enable them one at a time and see the effect of each — no surprises, no lockouts on activation.

## Features

- **Login protection** — custom (hidden) login URL, honeypot, brute-force rate limiting with temporary lockout, and an IP whitelist.
- **Two-factor authentication** — authenticator-app TOTP with QR enrolment, downloadable recovery codes, admin reset, per-role enforcement, and an XML-RPC 2FA policy.
- **reCAPTCHA** — the v2 checkbox or invisible v3 (with score threshold and email fallback) on the login, registration, and lost-password forms.
- **Password policy** — minimum length, character-class rules, and blocking the username/email as the password.
- **Malware scanner** — core-file checksum verification plus a suspicious-code pattern engine (report-only).
- **File & server hardening** — block sensitive files, backup/database dumps, and your own patterns; disable directory listing and PHP execution in uploads; hide the version and server headers; block user enumeration.
- **Firewall** — blocks common SQL-injection, XSS, file-inclusion, and command-injection patterns plus known scanner bots.
- **XML-RPC control** — disable it entirely or pingbacks only, with per-request logging.
- **Audit log & alerts** — a searchable, filterable, live-updating, CSV-exportable log with a configurable retention period, and grouped email alerts for critical events.
- **Dashboard** — a security overview showing the threats blocked in the last 24 hours and the next protection to switch on.

## Requirements

- WordPress 6.8+
- PHP 8.1–8.4

## Installation

1. Copy this folder to `wp-content/plugins/qevix-shield/`, or install the ZIP from **Plugins → Add New**.
2. Activate **Qevix Shield** under **Plugins**.
3. Open **Qevix Shield → Dashboard**, then switch on the protections you want, one at a time, from each Settings tab.

> **Hiding the login URL** is off until you enable it on the *Hide Admin Panel* tab. Once on, `wp-login.php` is blocked and login moves to `https://your-site/<slug>` — note the slug somewhere safe first. Plugins with their own front-end login pages (WooCommerce, membership/LMS, page-builder widgets) keep working; just check anything that *prints* a login link to anonymous visitors, since that link is rewritten to the secret slug.

## Qevix Shield Pro

Everything above is free and works standalone. The paid [Qevix Shield Pro](https://qevixlabs.com/products/qevix-shield) add-on extends these modules — full-site malware scanning (plugins, themes, uploads, and the database) with quarantine and scheduled scans, breached-password checks, advanced login blocking, all-user session management, multi-channel alerts (SMS, WhatsApp, Slack, Discord, webhooks), trusted devices for 2FA, and reCAPTCHA on WooCommerce forms. It installs alongside this plugin and never replaces it.

## Uninstall

Deleting the plugin drops the `wp_qevix_shield_logs` table and all settings, unless *General → Keep settings and logs if this plugin is deleted* is checked. Managed `.htaccess` rules are always removed (they are behaviour, not data).

## Development

No build step, linter, or test suite. Validate PHP syntax with:

```sh
find . -name "*.php" -print0 | xargs -0 -n1 php -l
```

The `Qevix Shield Pro Min:` plugin header mirrors the `QEVIX_SHIELD_MIN_PRO_VERSION` constant beside it (bump both together) — the oldest Pro version this release pairs with. It is deliberately not a `Requires`: the plugin never requires or reads Pro state.

## License

GPL-2.0-or-later. See [license.txt](license.txt).
