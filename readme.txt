=== Qevix Shield ===
Contributors: qevixlabs
Tags: security, firewall, two factor authentication, malware scanner, login security
Requires at least: 6.8
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Login protection, two-factor auth, reCAPTCHA, malware scanning, a firewall, and an audit log with alerts. Every protection off until you turn it on.

== Description ==

Qevix Shield hardens the parts of WordPress that attackers hit first — the login form, XML-RPC, file access, and the URLs that leak information about your install. Everything it blocks is written to a searchable audit log, and critical events can email you automatically.

It installs **neutral**: activating it changes nothing about your site. Every protection stays off until you switch it on, so you enable them one at a time and see the effect of each — no surprises, no lockouts on activation. (The audit log runs from the start; that is monitoring only.)

= Why Qevix Shield =

* **Turning it on breaks nothing.** Every protection ships off. Enable them one at a time and watch what each does.
* **You can't lock yourself out.** A one-line safe mode in `wp-config.php` suspends everything without touching your settings. reCAPTCHA keys must pass a live test before they can be enabled, 2FA has recovery codes plus an admin reset, and lockouts are temporary.
* **One plugin, the whole checklist.** Hidden login URL, brute-force lockouts, 2FA, reCAPTCHA, password rules, XML-RPC control, malware scanning, file and server hardening, a firewall, and an audit log — instead of five single-purpose plugins.
* **You hear about it.** Every block, login, and admin action lands in a live, searchable log you can export to CSV. Critical events email you as one grouped summary — an attack wave is one message, not fifty.
* **No measurable slowdown.** With everything enabled, response times match the deactivated site within measurement noise. Nothing waits on an external service.
* **It leaves your other plugins alone.** No patching or overriding another plugin's code — WooCommerce, membership, and front-end login pages keep working, even with the hidden login URL on.
* **Everything here is free.** No account, no license key, no trial, no feature that expires, no greyed-out controls. The optional Pro add-on only adds capabilities of its own on top — it never unlocks something already in this plugin.

= Login protection =

* Move login off `/wp-login.php` to a custom slug of your choosing (off by default).
* Choose what a blocked request sees: a 404, your homepage, or a custom redirect.
* A honeypot field catches basic bots without affecting real visitors.
* Rate-limit failed logins and temporarily lock out an IP after too many failures.
* Whitelist trusted IPs so they're never rate-limited or locked out.

= Two-factor authentication (2FA) =

* One-time codes from any authenticator app (Google Authenticator, Authy, 1Password, and similar). Setup is per-user: scan a QR code, confirm a code.
* Recovery codes issued at setup with a one-click download, plus an admin reset — a lost phone is never a lockout.
* Require 2FA for any role you choose: an enforced user who hasn't enrolled sees only the setup screen until they do.
* Closes the XML-RPC side door: require the code appended to the password over XML-RPC, or block XML-RPC password logins for 2FA accounts. Application passwords are unaffected.

= reCAPTCHA =

* Google reCAPTCHA on your login, registration, and lost-password forms — the v2 "I'm not a robot" checkbox or invisible v3 scoring, your choice.
* v3 adds a tunable score threshold and an optional email fallback: a real person the score misjudges gets a one-time sign-in link instead of a dead end.
* A required "Test keys" step proves your keys work before the switch can be turned on — a wrong-type key would otherwise break login for everyone, including you. Fails open if Google is unreachable, so an outage never locks you out.

= Password policy =

* Require a minimum length and character classes (upper, lower, number, symbol).
* Block passwords that are just the account's username or email.

= XML-RPC protection =

* One switch to disable all XML-RPC methods, or disable pingbacks only.
* Log every XML-RPC request with its method and whether it was allowed or blocked.

= Malware scanner =

* Compare WordPress core files against official checksums to spot tampering.
* A pattern engine flags suspicious PHP, obfuscated JavaScript, and common malware signatures.
* Report-only: it shows what it found without changing any files.

= File & server hardening =

* Block direct access to sensitive files (`.env`, `.git`, `wp-config.php`, and more).
* Block backup and database dumps (`.sql`, `.bak`, `.tar.gz`, `.wpress`), plus your own filenames or `*.extension` patterns.
* Disable directory listing and PHP execution in uploads. Writes the Apache `.htaccess` rules for you, and shows the nginx equivalent to paste.
* Hide the WordPress version, REST API discovery links, and identifying server headers. Block author/user enumeration.
* A lightweight firewall blocks common SQL-injection, XSS, file-inclusion, and command-injection patterns plus known scanner user agents.

= Sessions, audit log & dashboard =

* Every user can see and end their own active login sessions; a password reset logs out that account's other sessions.
* The audit log records every login, admin action, and block with the who/what/when/where — searchable, filterable, live-updating, CSV-exportable, with a configurable retention period.
* Critical events email your administrators, grouped into one summary instead of fifty (opt-in).
* A WordPress dashboard widget shows threats blocked in the last 24 hours and recommends the next protection to switch on.
* Grant other roles manage or read-only access to Qevix Shield without full `manage_options`.

= Qevix Shield Pro =

Qevix Shield is complete on its own, and everything above is free and stays free. The optional Pro add-on (sold at qevixlabs.com, never required) adds what happens **after** detection:

* **Full-site malware scanning** — plugins, themes, uploads, and the database, with quarantine, extra web-shell signatures, and scheduled daily/weekly scans.
* **Breached-password protection** — a privacy-preserving check against the Have I Been Pwned database of a billion leaked passwords, plus a common-password blocklist, expiration, reuse prevention, and forced resets.
* **Advanced login blocking** — permanent IP blacklists, user-agent filtering, auto-blacklisting of repeat offenders, and CIDR whitelists.
* **Multi-channel alerts** — SMS, WhatsApp, Slack, Discord, and webhooks, as grouped digests routed by category and severity.
* **Session & access control** — an admin view of every user's sessions with idle-timeout enforcement, plus WP-CLI commands.
* **Extras** — trusted devices and an emailed backup code for 2FA, reCAPTCHA on WooCommerce forms, and granular XML-RPC (authenticated-only, allowlist, or trusted IPs).

== External services ==

Qevix Shield makes no external requests by default. Two optional features each contact one service, and only after you set them up:

**Google reCAPTCHA** — used only if you enable reCAPTCHA and enter your own Google keys. The login page then loads Google's reCAPTCHA script, and each protected attempt sends the reCAPTCHA token, your secret key, and the visitor's IP to Google's verification endpoint (`https://www.google.com/recaptcha/api/siteverify`). The "Test keys" button also contacts Google. Provided by Google: [terms](https://policies.google.com/terms), [privacy policy](https://policies.google.com/privacy).

**WordPress.org checksums API** — when you run a core-file scan, the plugin fetches your version's official checksums via WordPress core's own `get_core_checksums()`, which contacts `api.wordpress.org`. Only your WordPress version and locale are sent. Provided by WordPress.org: [privacy policy](https://wordpress.org/about/privacy/).

Built-in alerts are sent by **email** through your site's own mail configuration — no third party is contacted. The other alert channels (Slack, Discord, webhooks, SMS, WhatsApp) and the Have I Been Pwned check belong to the separate Qevix Shield Pro add-on; this free plugin never contacts them. No other data leaves your site — audit logs, lockout records, 2FA secrets, and settings live only in your own database.

== Installation ==

1. Upload the `qevix-shield` folder to `/wp-content/plugins/`, or install it from the Plugins screen.
2. Activate the plugin.
3. Open **Qevix Shield → Settings** and switch on the protections you want, one at a time.

== Frequently Asked Questions ==

= Is everything really free? =

Yes. Every feature on this page works the day you install it — no account, no license key, no trial, no expiry, and no greyed-out settings. The separate Pro add-on adds its own extra capabilities on top; it never unlocks anything already in this plugin.

= Do I need to configure anything after activating? =

Only what you want. Qevix Shield installs neutral — activation changes nothing about your site. You switch on each protection deliberately from its settings tab, so you always know what's active and why. (The audit log starts monitoring right away, but it doesn't alter your site.)

= Will it slow down my site? =

No measurable difference. With every protection enabled, response times match the same site with the plugin deactivated, within measurement noise. There is no external service your visitors wait on.

= Will it lock me out of my own site? =

It's built not to. Rate limiting and IP lockouts only apply to failed logins and are temporary; add your own IP to the whitelist to be certain. Login-URL hiding is off by default — if you enable it, bookmark the new address first. And there's always the recovery switch below.

= I've locked myself out. How do I recover? =

Add this one line to `wp-config.php`:

`define( 'QEVIX_SHIELD_SAFE_MODE', true );`

It suspends every Qevix Shield protection without changing any of your settings, so you can log in and fix things, then remove the line. It works even when you can't reach the dashboard, because `wp-config.php` loads before the plugin. (One exception: server rules already written to `.htaccess`/nginx are enforced by the web server — edit that block out by hand if you enabled them.)

= Does it work with WooCommerce and plugins that have their own login pages? =

Yes. WooCommerce, membership and LMS plugins, and page-builder login widgets keep working, including with the hidden login URL on — they use their own pages, not `wp-login.php`.

= I use the Pro add-on. Do the versions need to match? =

They release together with the same version number, and matching is the supported pairing. If they drift, nothing breaks: Pro shows a notice telling you which side to update.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
