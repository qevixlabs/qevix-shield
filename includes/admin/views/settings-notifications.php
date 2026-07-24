<?php
/**
 * Notifications settings section (form only). Expects $settings.
 *
 * Single-form pattern (same as Login Protection/Password Security/XML-RPC/
 * Malware): ONE form, ONE Save button. Free owns the email channel
 * and the "critical events always fire email" guarantee — always
 * editable. The pro "Advanced Notifications" fields (SMS/webhook/Slack/Discord
 * channels, per-event notify list, severity threshold)
 * sit in the SAME form:
 *
 *   - Unlicensed: no pro fields at all — `QevixShield_Menu::render_pro_upsell()`
 *     draws a card listing what Pro adds here, with the two standard CTAs.
 *     Nothing inert or greyed out is shown in place of the fields.
 *   - Licensed, but the viewer lacks manage_options: the real fields render
 *     read-only inside a bordered `<fieldset disabled>` with a lock-icon
 *     legend — a preview of settings that exist, not of settings to be bought.
 *   - Licensed AND the viewer is an admin: the fields render as a plain
 *     section, values filled by pro through
 *     `qevix_shield_notifications_pro_values`. The single Save button persists
 *     both halves (free keys via free's handler, pro keys via its
 *     `qevix_shield_notifications_save_pro` listener).
 *
 * Free's save handler never persists the pro keys in any case; it only fires
 * `qevix_shield_notifications_save_pro`, which has no listener unless a licensed
 * pro plugin is installed.
 *
 * "Send Test Notification" is a distinct ACTION (not a saved setting, like
 * Password Security's Force Reset), so it keeps its own small form/button,
 * rendered by pro via `qevix_shield_notifications_pro_test` after this form
 * closes (HTML forms can't nest).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$isPro       = (bool) apply_filters( 'qevix_shield_is_pro_active', false );
$proEditable = $isPro && current_user_can( 'manage_options' );

$proValues = (array) apply_filters(
	'qevix_shield_notifications_pro_values',
	array(
		'notify_min_severity'    => 'critical',
		// Display defaults for the locked (pro-inactive) preview — mirror pro's
		// real defaults so the teaser shows the default-on state; the Qevix Shield
		// self-monitoring category is on by default (user can uncheck once pro
		// is active). Pro overlays actual saved values via the filter below.
		'notify_events'          => array( 'auth', 'admin', 'plugins', 'wordpress', 'qevix-shield' ),
		'notify_sms_enabled'     => false,
		'notify_sms_provider'    => 'twilio',
		'notify_sms_to'          => '',
		'notify_sms_from'        => '',
		'notify_sms_sid'         => '',
		'notify_webhook_enabled' => false,
		'notify_webhook_url'     => '', // write-only: pro never echoes the saved URL back.
		'webhook_url_set'        => false,
		'webhook_url_hint'       => '',
		'notify_webhook_format'  => 'generic',
		'sms_token_set'          => false,
	)
);
$notifyEvents = (array) $proValues['notify_events'];

$eventLabels = array(
	'auth'      => __( 'Authentication events (login, logout, password, MFA)', 'qevix-shield' ),
	'admin'     => __( 'Admin events (user create/delete, role changes)', 'qevix-shield' ),
	'plugins'   => __( 'Plugin / theme events (install, activate, update, delete)', 'qevix-shield' ),
	'wordpress' => __( 'WordPress events (core update, settings, firewall, XML-RPC)', 'qevix-shield' ),
	'qevix-shield' => __( 'Qevix Shield events (option enabled/disabled, updated, settings changed)', 'qevix-shield' ),
);

$proLock = $proEditable ? '' : '<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span> ';
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="notifications" />

	<h3><?php esc_html_e( 'Email Notifications', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'The built-in channel: critical events are emailed to the recipients configured below.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Email Alerts', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Emails the recipients below when a CRITICAL event is logged — e.g. malware found, a brute-force lockout, an XML-RPC attack. Events arriving close together are <strong>grouped into one summary email</strong> (sent about 2 minutes after the first event) instead of one email each — so an attack wave means one message listing everything, not an inbox flood. Routine info/warning events never email. Off by default: until you tick this, even critical events stay silent (visible only on the Audit Log screen).', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="alerts_enabled" value="1" <?php checked( $settings->get( 'alerts_enabled', false ) ); ?> /> <?php esc_html_e( 'Email critical security events (malware detected, file modified, XML-RPC attack, brute force, IP blocked)', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default — while unticked, no alert emails are sent, critical events included. Events occurring close together are grouped into a single summary email.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="admin_emails"><?php esc_html_e( 'Recipients', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Who gets the alert emails. The WordPress administration email (greyed out) is always included; add extra addresses below it — e.g. <code>security@example.com, ops@example.com</code> — comma-separated or one per line.', 'qevix-shield' ) ); ?>
				<?php $wpAdminEmail = (string) get_option( 'admin_email' ); ?>
				<p class="qevix-shield-field-row">
					<input type="email" value="<?php echo esc_attr( $wpAdminEmail ); ?>" class="regular-text" readonly disabled />
					<span class="description"><?php esc_html_e( 'WordPress administration email — always notified.', 'qevix-shield' ); ?></span>
				</p>
				<textarea name="admin_emails" id="admin_emails" rows="3" class="large-text" placeholder="security@example.com, ops@example.com"><?php echo esc_textarea( (string) $settings->get( 'admin_emails', '' ) ); ?></textarea>
				<p class="description">
					<?php
					printf(
						/* translators: 1: WordPress admin email address, 2: link to WordPress Settings → General */
						esc_html__( 'Notification recipients are configured here. The WordPress administration email (%1$s) is always notified; that address is managed by WordPress and can only be changed under %2$s. Add any extra recipients above — one per line or comma-separated. These addresses receive the email alerts; the Pro SMS/WhatsApp and webhook channels have their own recipients below.', 'qevix-shield' ),
						'<code>' . esc_html( $wpAdminEmail ) . '</code>',
						'<a href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'WordPress Settings &rarr; General', 'qevix-shield' ) . '</a>'
					);
					?>
				</p>
			</td>
		</tr>
	</table>

	<?php if ( $isPro ) : ?>

	<?php if ( $proEditable ) : ?>
	<h3><?php esc_html_e( 'Advanced Notifications', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Pro delivery on top of the email channel above: SMS/WhatsApp and webhooks, filtered by severity and event category.', 'qevix-shield' ); ?></p>
	<?php else : ?>
	<fieldset class="qevix-shield-pro-fieldset" disabled>
		<legend>
			<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span>
			<?php esc_html_e( 'Advanced Notifications (Pro)', 'qevix-shield' ); ?>
		</legend>
		<p class="description"><?php esc_html_e( 'These settings can only be changed by an administrator.', 'qevix-shield' ); ?></p>
	<?php endif; ?>

		<table class="form-table">
			<tr>
				<th scope="row"><label for="notify_min_severity"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Minimum Severity', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Noise filter for the Pro channels (SMS/webhook). At <strong>Warning and above</strong>, failed-login warnings reach your Slack/phone; at <strong>Critical only</strong>, just the serious stuff does. Routine <strong>info</strong> events are log detail and are never sent to any channel. Events are grouped into one digest per batch, not one message each.', 'qevix-shield' ) ); ?>
					<select id="notify_min_severity" name="notify_min_severity" class="qevix-shield-min-select">
						<?php $minSeverity = 'warning' === $proValues['notify_min_severity'] || 'info' === $proValues['notify_min_severity'] ? 'warning' : 'critical'; ?>
						<option value="warning" <?php selected( 'warning', $minSeverity ); ?>><?php esc_html_e( 'Warning and above', 'qevix-shield' ); ?></option>
						<option value="critical" <?php selected( 'critical', $minSeverity ); ?>><?php esc_html_e( 'Critical only', 'qevix-shield' ); ?></option>
					</select>
					<p class="description"><?php esc_html_e( 'Only events at or above this severity are sent to the pro channels below; info events never notify. The free email alert covers critical events independently of this filter.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Event Categories', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Which kinds of events reach the Pro channels at all. Example: keep <strong>Authentication</strong> and <strong>Qevix Shield</strong> checked but uncheck <strong>Plugin / theme</strong> if routine update notices are noise for you. An event must pass BOTH this category filter and the severity filter above.', 'qevix-shield' ) ); ?>
					<?php foreach ( $eventLabels as $key => $label ) : ?>
						<label class="qevix-shield-block-label">
							<input type="checkbox" name="notify_events[]" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $notifyEvents, true ) ); ?> />
							<?php echo esc_html( $label ); ?>
						</label>
					<?php endforeach; ?>
					<p class="description"><?php esc_html_e( 'Only the checked categories trigger a pro-channel notification.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
		</table>

		<h3><?php esc_html_e( 'SMS / WhatsApp', 'qevix-shield' ); ?></h3>
		<p class="description"><?php esc_html_e( 'Send the digest to a phone via Twilio SMS or the WhatsApp Cloud API.', 'qevix-shield' ); ?></p>
		<table class="form-table">
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Enable SMS', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Delivers alerts to a phone — useful for critical events that must wake someone up, since email can sit unread. Events are grouped into <strong>one short digest message per batch</strong> (about 5 minutes after the first event), e.g. "14 security events (3 critical). Top: login_failed ×9" — an attack wave costs one SMS, not dozens. Needs an account with the selected gateway (Twilio or WhatsApp Cloud API); message fees are the gateway\'s, not Qevix Shield\'s.', 'qevix-shield' ) ); ?><label><input type="checkbox" name="notify_sms_enabled" value="1" <?php checked( $proValues['notify_sms_enabled'] ); ?> /> <?php esc_html_e( 'Send notifications by SMS / WhatsApp', 'qevix-shield' ); ?></label></td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_sms_provider"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'SMS Gateway', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'The service that actually sends the message. <strong>Twilio</strong> sends real SMS text messages (needs a Twilio account + phone number). <strong>WhatsApp Cloud API</strong> sends WhatsApp messages via Meta\'s business platform. The credential fields below change meaning depending on this choice.', 'qevix-shield' ) ); ?>
					<select id="notify_sms_provider" name="notify_sms_provider" class="qevix-shield-min-select">
						<option value="twilio" <?php selected( 'twilio', $proValues['notify_sms_provider'] ); ?>><?php esc_html_e( 'Twilio (SMS)', 'qevix-shield' ); ?></option>
						<option value="whatsapp" <?php selected( 'whatsapp', $proValues['notify_sms_provider'] ); ?>><?php esc_html_e( 'WhatsApp Cloud API', 'qevix-shield' ); ?></option>
					</select>
					<br />
					<?php // Only the selected gateway's help link shows; assets/js/notifications.js re-syncs on dropdown change. ?>
					<a class="qevix-shield-external-link" id="qevix-shield-sms-help-twilio" href="https://console.twilio.com/" target="_blank" rel="noopener" <?php echo 'twilio' === $proValues['notify_sms_provider'] ? '' : 'hidden'; ?>>
						<?php esc_html_e( 'Need help? Twilio: get your Account SID, Auth Token and sender number from the Twilio Console', 'qevix-shield' ); ?>
						<span class="dashicons dashicons-external" aria-hidden="true"></span>
					</a>
					<a class="qevix-shield-external-link" id="qevix-shield-sms-help-whatsapp" href="https://developers.facebook.com/apps/" target="_blank" rel="noopener" <?php echo 'whatsapp' === $proValues['notify_sms_provider'] ? '' : 'hidden'; ?>>
						<?php esc_html_e( 'Need help? WhatsApp: get your phone-number ID and access token from the Meta app dashboard', 'qevix-shield' ); ?>
						<span class="dashicons dashicons-external" aria-hidden="true"></span>
					</a>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_sms_to"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Recipient Mobile Number(s)', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'The phone number(s) that receive the alerts, in international E.164 format: a leading <code>+</code>, then country code and number, no spaces — e.g. <code>+14155550123</code> (US) or <code>+41791234567</code> (Switzerland). Separate several with commas.', 'qevix-shield' ) ); ?>
					<input type="text" id="notify_sms_to" name="notify_sms_to" value="<?php echo esc_attr( $proValues['notify_sms_to'] ); ?>" class="regular-text" placeholder="+14155550123, +447700900123" />
					<p class="description"><?php esc_html_e( 'Where alerts are delivered. Use E.164 format (leading +, country code). Separate multiple numbers with commas.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_sms_from"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Sender Number / ID', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'What the message is sent FROM. Twilio: the phone number you bought in the Twilio console, e.g. <code>+14155551234</code>. WhatsApp: the numeric <strong>phone-number ID</strong> from Meta\'s WhatsApp app dashboard (an ID like <code>106540352242922</code>, not the phone number itself).', 'qevix-shield' ) ); ?>
					<input type="text" id="notify_sms_from" name="notify_sms_from" value="<?php echo esc_attr( $proValues['notify_sms_from'] ); ?>" class="regular-text" placeholder="+14155551234" />
					<p class="description"><?php esc_html_e( 'Twilio: your Twilio "from" phone number. WhatsApp: your WhatsApp phone-number ID.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_sms_sid"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Account SID', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Twilio only: the account identifier starting with <code>AC…</code>, shown on your Twilio Console dashboard (twilio.com → Console → Account Info). Leave blank when using WhatsApp.', 'qevix-shield' ) ); ?>
					<input type="text" id="notify_sms_sid" name="notify_sms_sid" value="<?php echo esc_attr( $proValues['notify_sms_sid'] ); ?>" class="regular-text" placeholder="ACxxxxxxxxxxxxxxxx" />
					<p class="description"><?php esc_html_e( 'Twilio Account SID. Leave blank for WhatsApp.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_sms_token"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Auth Token / Access Token', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'The secret that authorizes sending: Twilio\'s Auth Token (next to the Account SID in the console) or the WhatsApp Cloud API access token. Saved encrypted and never shown again — the field stays blank on purpose; leave it blank to keep the stored token, type a new one to replace it.', 'qevix-shield' ) ); ?>
					<input type="password" id="notify_sms_token" name="notify_sms_token" value="" class="regular-text" autocomplete="new-password" placeholder="<?php echo $proValues['sms_token_set'] ? esc_attr__( '••••••• (saved — leave blank to keep)', 'qevix-shield' ) : ''; ?>" />
					<p class="description"><?php esc_html_e( 'Twilio Auth Token, or the WhatsApp Cloud API access token. Stored encrypted at rest; leave blank to keep the existing value.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
		</table>
		<?php
		if ( ! empty( $proValues['notify_sms_enabled'] ) ) {
			$smsMissing = array();
			if ( '' === trim( (string) $proValues['notify_sms_to'] ) ) {
				$smsMissing[] = __( 'recipient number', 'qevix-shield' );
			}
			if ( '' === trim( (string) $proValues['notify_sms_from'] ) ) {
				$smsMissing[] = __( 'sender number/ID', 'qevix-shield' );
			}
			if ( 'twilio' === $proValues['notify_sms_provider'] && '' === trim( (string) $proValues['notify_sms_sid'] ) ) {
				$smsMissing[] = __( 'Account SID', 'qevix-shield' );
			}
			if ( empty( $proValues['sms_token_set'] ) ) {
				$smsMissing[] = __( 'auth token', 'qevix-shield' );
			}
			if ( ! empty( $smsMissing ) ) {
				QevixShield_Menu::dependency_notice( sprintf(
					/* translators: %s: comma-separated list of missing SMS fields */
					__( 'SMS / WhatsApp is on but not fully configured — still needed: %s. No messages will send until these are set.', 'qevix-shield' ),
					'<strong>' . esc_html( implode( ', ', $smsMissing ) ) . '</strong>'
				) );
			}
		}
		?>

		<?php $sampleSite = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ); ?>
		<details class="qevix-shield-guide">
			<summary><span class="dashicons dashicons-editor-help" aria-hidden="true"></span> <?php esc_html_e( 'Worried about cost or noise? How often alerts send, with sample messages', 'qevix-shield' ); ?></summary>
			<div class="qevix-shield-guide-body">
				<p><?php esc_html_e( 'You get one short message per incident, not one per event: the first qualifying event opens a ~5-minute collection window, and everything inside it is grouped into a single digest. A brute-force wave of 50 events costs ONE message. On a quiet day, nothing is sent at all.', 'qevix-shield' ); ?></p>
				<p><?php esc_html_e( 'Only events at or above your Minimum Severity, in the Event Categories you checked, count toward a message — routine info events never notify on any channel. Fewer categories and "Critical only" means fewer (or zero) messages.', 'qevix-shield' ); ?></p>
				<p><strong><?php esc_html_e( 'The digest — the message you will normally receive:', 'qevix-shield' ); ?></strong></p>
				<pre class="qevix-shield-sample"><?php echo esc_html( sprintf( /* translators: %s: site name */ __( '[%s] 14 security events since 3:58 pm (3 critical, 11 warning). Top: login_failed ×9, ip_locked_out ×3, xmlrpc:pingback.ping ×2.', 'qevix-shield' ), $sampleSite ) ); ?></pre>
				<p><strong><?php esc_html_e( 'Single-event message — only the "Send Test Notification" button sends this form:', 'qevix-shield' ); ?></strong></p>
				<pre class="qevix-shield-sample"><?php echo esc_html( sprintf( /* translators: %s: site name */ __( '[%s] CRITICAL security event: ip_locked_out — user admin, IP 203.0.113.42 at 2026-07-17 16:54:43', 'qevix-shield' ), $sampleSite ) ); ?></pre>
				<p><?php esc_html_e( 'Cost per digest: one WhatsApp message, or 2–3 SMS segments on Twilio (the digest is about 140 characters, and its × / — characters use Unicode encoding, which lowers the SMS segment size to 70 characters).', 'qevix-shield' ); ?></p>
			</div>
		</details>

		<details class="qevix-shield-guide">
			<summary><span class="dashicons dashicons-editor-help" aria-hidden="true"></span> <?php esc_html_e( 'New to Twilio or WhatsApp? Step-by-step: getting your gateway credentials', 'qevix-shield' ); ?></summary>
			<div class="qevix-shield-guide-body">
				<p><strong><?php esc_html_e( 'Twilio (SMS)', 'qevix-shield' ); ?></strong></p>
				<ol>
					<li>
						<?php esc_html_e( 'Create a free trial account — no credit card needed; the trial includes free product units (e.g. 100 SMS messages):', 'qevix-shield' ); ?>
						<br />
						<a href="https://www.twilio.com/try-twilio" target="_blank" rel="noopener">https://www.twilio.com/try-twilio <span class="dashicons dashicons-external" aria-hidden="true"></span></a>
					</li>
					<li><?php esc_html_e( 'The Console home page (console.twilio.com) shows your Account SID (starts with AC…) and Auth Token — copy each into its matching field above.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Get your trial phone number in the Console under Products & Services → Numbers & senders → Overview → "Set up a new phone number" (a trial account can hold one Twilio number). Enter it as the Sender Number in international format, e.g. +14155551234.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Trial limitation: a trial account can call or message verified recipients only — add each recipient under Verified Caller IDs → "Add a new Caller ID" first. Upgrade the account to message any number.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Choose "Twilio (SMS)" as the SMS Gateway above, enter the recipient number(s), tick "Enable SMS" and press Save. Then press "Send Test Notification" below to confirm delivery.', 'qevix-shield' ); ?></li>
				</ol>
				<p><strong><?php esc_html_e( 'WhatsApp Cloud API', 'qevix-shield' ); ?></strong></p>
				<ol>
					<li>
						<?php esc_html_e( 'Open the Meta app dashboard, sign in with a Facebook account, and create an app with the "Connect with customers through WhatsApp" use case — a free test WhatsApp business number is created for you automatically:', 'qevix-shield' ); ?>
						<br />
						<a href="https://developers.facebook.com/apps/" target="_blank" rel="noopener">https://developers.facebook.com/apps/ <span class="dashicons dashicons-external" aria-hidden="true"></span></a>
					</li>
					<li><?php esc_html_e( 'In the app\'s left menu open WhatsApp → API Setup. Copy the numeric Phone number ID shown under the "From" number (the ID, not the phone number itself) into the Sender Number / ID field above.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Generate an access token on the same page and paste it into the Auth Token field. The dashboard token is temporary (roughly a day — Meta notes it "expires quickly and is not suitable for development") — for permanent alerts, create a System User token under Meta Business Settings with the whatsapp_business_messaging permission instead.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Still on API Setup, add each recipient under "To" → Manage phone number list; Meta sends that phone a confirmation code on WhatsApp. A test number can only message the few numbers on this list (the dashboard currently allows up to 5).', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Delivery rule: WhatsApp only delivers these alerts if the recipient has messaged your WhatsApp business number within the previous 24 hours — have each recipient send any message (e.g. "hi") to the number to open that window.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Leave Account SID blank for WhatsApp. Choose "WhatsApp Cloud API" as the SMS Gateway above, tick "Enable SMS" and press Save, then press "Send Test Notification".', 'qevix-shield' ); ?></li>
				</ol>
			</div>
		</details>

		<h3><?php esc_html_e( 'Webhook', 'qevix-shield' ); ?></h3>
		<p class="description"><?php esc_html_e( 'Push the digest to Slack, Discord, or your own endpoint over HTTP.', 'qevix-shield' ); ?></p>
		<table class="form-table">
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Enable Webhook', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Pushes matching events to another system over HTTP — the way to get alerts into Slack, Discord, or your own monitoring dashboard. Events are delivered as <strong>one digest per batch</strong> (about 5 minutes after the first event), not one request each, so a burst can\'t spam the receiving channel. Pick the format below and paste the destination URL.', 'qevix-shield' ) ); ?><label><input type="checkbox" name="notify_webhook_enabled" value="1" <?php checked( $proValues['notify_webhook_enabled'] ); ?> /> <?php esc_html_e( 'POST a JSON payload to a webhook URL', 'qevix-shield' ); ?></label></td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_webhook_format"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Payload Format', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Match this to the receiving end. <strong>Slack</strong> / <strong>Discord</strong>: choose these for their incoming-webhook URLs — the digest appears as one chat message per batch. <strong>Generic</strong>: a JSON digest (event counts by severity and action, plus the individual events) for your own endpoint or tools like Zapier/n8n.', 'qevix-shield' ) ); ?>
					<select id="notify_webhook_format" name="notify_webhook_format" class="qevix-shield-min-select">
						<option value="generic" <?php selected( 'generic', $proValues['notify_webhook_format'] ); ?>><?php esc_html_e( 'Generic (full event JSON)', 'qevix-shield' ); ?></option>
						<option value="slack" <?php selected( 'slack', $proValues['notify_webhook_format'] ); ?>><?php esc_html_e( 'Slack', 'qevix-shield' ); ?></option>
						<option value="discord" <?php selected( 'discord', $proValues['notify_webhook_format'] ); ?>><?php esc_html_e( 'Discord', 'qevix-shield' ); ?></option>
					</select>
					<p class="description"><?php esc_html_e( 'Slack/Discord use their incoming-webhook message shape; Generic posts a structured digest (counts + events) for a custom endpoint.', 'qevix-shield' ); ?></p>
					<?php // Only the selected format's help link shows; assets/js/notifications.js re-syncs on dropdown change. ?>
					<a class="qevix-shield-external-link" id="qevix-shield-web-help-generic" href="https://webhook.site" target="_blank" rel="noopener" <?php echo 'generic' === $proValues['notify_webhook_format'] ? '' : 'hidden'; ?>>
						<?php esc_html_e( 'Need help? No endpoint yet? Get a free capture URL from webhook.site to test with', 'qevix-shield' ); ?>
						<span class="dashicons dashicons-external" aria-hidden="true"></span>
					</a>
					<a class="qevix-shield-external-link" id="qevix-shield-web-help-slack" href="https://api.slack.com/apps" target="_blank" rel="noopener" <?php echo 'slack' === $proValues['notify_webhook_format'] ? '' : 'hidden'; ?>>
						<?php esc_html_e( 'Need help? Slack: create an app with an incoming webhook for your channel', 'qevix-shield' ); ?>
						<span class="dashicons dashicons-external" aria-hidden="true"></span>
					</a>
					<a class="qevix-shield-external-link" id="qevix-shield-web-help-discord" href="https://support.discord.com/hc/en-us/articles/228383668" target="_blank" rel="noopener" <?php echo 'discord' === $proValues['notify_webhook_format'] ? '' : 'hidden'; ?>>
						<?php esc_html_e( 'Need help? Discord: create a webhook under Server Settings → Integrations', 'qevix-shield' ); ?>
						<span class="dashicons dashicons-external" aria-hidden="true"></span>
					</a>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="notify_webhook_url"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Webhook URL', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Where the payload is POSTed. Slack: create one under api.slack.com → Incoming Webhooks (looks like <code>https://hooks.slack.com/services/…</code>). Discord: channel settings → Integrations → Webhooks. Use the "Send Test Notification" button below to confirm delivery — the test sends immediately, skipping the digest grouping.', 'qevix-shield' ) ); ?>
					<input type="url" id="notify_webhook_url" name="notify_webhook_url" value="" class="regular-text" autocomplete="off" placeholder="<?php echo ! empty( $proValues['webhook_url_set'] ) ? esc_attr( sprintf( /* translators: %s: masked host of the saved webhook URL */ __( '%s (saved — leave blank to keep)', 'qevix-shield' ), $proValues['webhook_url_hint'] ) ) : esc_attr__( 'https://hooks.slack.com/services/…', 'qevix-shield' ); ?>" />
					<p class="description"><?php esc_html_e( 'Stored securely and not shown again — the field stays blank on purpose. Leave it blank to keep the saved URL, or paste a new one to replace it. To stop sending, untick Enable Webhook above.', 'qevix-shield' ); ?></p>
					<?php
					if ( ! empty( $proValues['notify_webhook_enabled'] ) && empty( $proValues['webhook_url_set'] ) ) {
						QevixShield_Menu::dependency_notice( __( 'Webhook delivery is <strong>on</strong> but no URL is saved, so nothing is sent. Paste the destination URL above.', 'qevix-shield' ) );
					}
					?>
				</td>
			</tr>
		</table>

		<details class="qevix-shield-guide">
			<summary><span class="dashicons dashicons-editor-help" aria-hidden="true"></span> <?php esc_html_e( 'Worried about request volume? How often it posts, with sample payloads', 'qevix-shield' ); ?></summary>
			<div class="qevix-shield-guide-body">
				<p><?php esc_html_e( 'Webhooks follow the same grouping as SMS: one POST per ~5-minute batch, never one request per event — a burst of events cannot spam the receiving channel. The severity and category filters above apply too, and on a quiet day nothing is posted at all.', 'qevix-shield' ); ?></p>
				<p><strong><?php esc_html_e( 'Slack / Discord format — arrives as one chat message per batch:', 'qevix-shield' ); ?></strong></p>
				<pre class="qevix-shield-sample"><?php echo esc_html( sprintf( /* translators: %s: site name */ __( '[%s] 14 security events since 3:58 pm (3 critical, 11 warning). Top: login_failed ×9, ip_locked_out ×3, xmlrpc:pingback.ping ×2.', 'qevix-shield' ), $sampleSite ) ); ?></pre>
				<p><strong><?php esc_html_e( 'Generic format — one JSON document per batch, for your endpoint to parse:', 'qevix-shield' ); ?></strong></p>
				<pre class="qevix-shield-sample"><?php echo esc_html( '{
  "site": "' . home_url() . '",
  "digest": {
    "total": 14,
    "since": "2026-07-17T16:45:43+00:00",
    "severities": { "critical": 3, "warning": 11 },
    "actions": { "login_failed": 9, "ip_locked_out": 3, "xmlrpc:pingback.ping": 2 }
  },
  "events": [ { "action": "login_failed", "severity": "warning", "module": "auth", "status": "failed", "username": "admin", "ip": "203.0.113.42", "timestamp": "2026-07-17 16:45:43" }, "…" ]
}' ); ?></pre>
				<p><?php esc_html_e( 'The events list carries up to the 50 most recent events of the batch; the counters above it always cover everything, so nothing is lost when a huge burst is truncated. The "Send Test Notification" button posts one single-event payload immediately, outside the batching.', 'qevix-shield' ); ?></p>
			</div>
		</details>

		<details class="qevix-shield-guide">
			<summary><span class="dashicons dashicons-editor-help" aria-hidden="true"></span> <?php esc_html_e( 'New to webhooks? Step-by-step: connecting Slack, Discord, or your own endpoint', 'qevix-shield' ); ?></summary>
			<div class="qevix-shield-guide-body">
				<p><strong><?php esc_html_e( 'Slack', 'qevix-shield' ); ?></strong></p>
				<ol>
					<li>
						<?php esc_html_e( 'Open Slack\'s app console, press "Create App" (from scratch), give it any name — e.g. Qevix Shield Alerts — and pick your workspace:', 'qevix-shield' ); ?>
						<br />
						<a href="https://api.slack.com/apps" target="_blank" rel="noopener">https://api.slack.com/apps <span class="dashicons dashicons-external" aria-hidden="true"></span></a>
					</li>
					<li><?php esc_html_e( 'In the app\'s settings open "Incoming Webhooks" and switch "Activate Incoming Webhooks" on.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Press "Add New Webhook to Workspace", choose the channel that should receive the alerts, and press "Authorize".', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Copy the generated URL (it looks like https://hooks.slack.com/services/…) into the Webhook URL field above. Treat it like a password — anyone holding it can post into your channel, which is why the field never shows it again.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Set Payload Format to "Slack", tick "Enable Webhook", press Save, then press "Send Test Notification" — the test message appears in the channel.', 'qevix-shield' ); ?></li>
				</ol>
				<p><strong><?php esc_html_e( 'Discord', 'qevix-shield' ); ?></strong></p>
				<ol>
					<li><?php esc_html_e( 'In Discord, open your server\'s Server Settings → Integrations → Webhooks (you need the "Manage Webhooks" permission).', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Press "New Webhook", give it a name — e.g. Qevix Shield Alerts — and choose the channel that should receive the alerts.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Press "Copy Webhook URL" (it looks like https://discord.com/api/webhooks/…) and paste it into the Webhook URL field above. It embeds a secret token, so it is stored write-only like the Slack one.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Set Payload Format to "Discord", tick "Enable Webhook", press Save, then press "Send Test Notification" — the test message appears in the channel.', 'qevix-shield' ); ?></li>
				</ol>
				<p><strong><?php esc_html_e( 'Your own endpoint (Generic)', 'qevix-shield' ); ?></strong></p>
				<ol>
					<li><?php esc_html_e( 'Any HTTPS URL that accepts a JSON POST works: your own script, a monitoring dashboard, or the catch-hook URL from automation tools like Zapier, Make, or n8n.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'The Generic format posts a structured digest — event counts by severity and action, plus the individual events — so your endpoint can parse and route it.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'No endpoint yet? Open webhook.site (link under the format field) — it gives you a free unique URL that captures everything sent to it, so you can watch the payloads arrive in your browser while testing.', 'qevix-shield' ); ?></li>
					<li><?php esc_html_e( 'Paste the URL above, set Payload Format to "Generic (full event JSON)", tick "Enable Webhook", press Save, then press "Send Test Notification".', 'qevix-shield' ); ?></li>
				</ol>
			</div>
		</details>
	<?php if ( ! $proEditable ) : ?>
	</fieldset>
	<?php endif; ?>

	<?php endif; // $isPro ?>

	<?php submit_button( __( 'Save Changes', 'qevix-shield' ) ); ?>
</form>

<?php if ( ! $isPro ) : ?>
	<?php
	// The paid add-on's pitch sits BELOW the free form as a clearly separate
	// block — the free email-alert settings above are complete and save on
	// their own.
	QevixShield_Menu::render_pro_upsell(
		__( 'Advanced Notifications', 'qevix-shield' ),
		__( 'Qevix Shield Pro delivers security alerts beyond the free email channel:', 'qevix-shield' ),
		array(
			__( 'SMS alerts via Twilio, or WhatsApp via Meta\'s Cloud API', 'qevix-shield' ),
			__( 'Slack, Discord, or any custom webhook delivery', 'qevix-shield' ),
			__( 'Route by event category — auth, admin, plugins, WordPress, Qevix Shield', 'qevix-shield' ),
			__( 'Severity threshold and batched digests instead of one message per event', 'qevix-shield' ),
			__( 'Send a test notification to verify every channel', 'qevix-shield' ),
		)
	);
	?>
<?php endif; ?>

<?php
/**
 * Send Test Notification — a distinct action, not a
 * saved setting, so it keeps its own small form/button after this one closes
 * (HTML forms can't nest). Pro self-gates on QevixShield_Pro_License::is_valid()
 * and renders nothing when unlicensed.
 */
do_action( 'qevix_shield_notifications_pro_test', $isPro );
