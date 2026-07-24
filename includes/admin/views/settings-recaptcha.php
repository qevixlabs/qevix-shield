<?php
/**
 * reCAPTCHA tab (free-owned, single-form pattern). Expects: $isPro, $version,
 * $threshold, $settings (QevixShield_Settings), $notices.
 *
 * EVERY control on this tab is available on every tier — Enable, Site/Secret
 * keys, Version (v2 AND v3), Score Threshold, Email Verification Fallback and
 * Protect Forms (login / register / lost-password). This plugin implements all
 * of them, so none may be gated on a licence (wp.org Guideline 5). The only
 * thing a companion Pro plugin adds here is coverage of forms this plugin does
 * not implement (WooCommerce my-account / checkout) plus the bridge actions for
 * other plugins' forms; $isPro therefore only ever changes wording, never
 * whether a control is editable.
 *
 * Help text adapts to $isPro so it is accurate both standalone and with pro.
 *
 * $isVerified says whether the SAVED Site Key + Version + Secret is the trio
 * that passed the "Test keys" preflight. Until it has, the save handler refuses
 * to turn the master switch on — a mismatched key type produces no token in the
 * browser at all, which at login time is indistinguishable from a stripped
 * field and therefore locks every user out. See QevixShield_Recaptcha::ajax_test().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$siteKey     = (string) $settings->get( 'recaptcha_site_key', '' );
$secretSaved = '' !== trim( (string) $settings->get( 'recaptcha_secret_key', '' ) );
$enabled     = (bool) $settings->get( 'recaptcha_enabled', false );
$hasKeys     = '' !== trim( $siteKey ) && $secretSaved;
?>
<h3><?php esc_html_e( 'reCAPTCHA', 'qevix-shield' ); ?></h3>
<p class="description">
	<?php esc_html_e( 'Tell humans and bots apart before your login, registration, and lost-password forms are accepted.', 'qevix-shield' ); ?>
</p>

<?php
// NOTE: the "reCAPTCHA settings saved." confirmation is rendered ONCE by the
// shared wrapper (views/settings.php, which prints "<Tab> settings saved." on
// ?updated). Do NOT re-add it here or it shows twice.
//
// Validation notices from the last save (invalid key rejected / enable blocked).
foreach ( (array) ( $notices ?? array() ) as $noticeMsg ) :
	?>
	<div class="notice notice-error"><p><?php echo esc_html( $noticeMsg ); ?></p></div>
	<?php
endforeach;
?>

<?php if ( QevixShield_Recaptcha::is_bypassed() ) : ?>
	<div class="notice notice-warning"><p>
		<?php esc_html_e( 'reCAPTCHA is switched OFF by a wp-config.php constant (Safe Mode or a disable switch — an emergency bypass to recover from a lockout). Your settings below are saved but not enforced until that line is removed.', 'qevix-shield' ); ?>
	</p></div>
<?php endif; ?>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_recaptcha' ); ?>
	<input type="hidden" name="action" value="qevix_shield_recaptcha_save" />

	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Enable reCAPTCHA', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Google reCAPTCHA tells humans and bots apart before a form is accepted, stopping automated login and registration floods. You need free keys from Google first: google.com/recaptcha → Admin Console → register your site, then paste the two keys below.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="recaptcha_enabled" value="1" <?php checked( $enabled ); ?> /> <?php esc_html_e( 'Turn on reCAPTCHA protection', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Master switch — the forms below are only protected while this is checked, both keys are filled in, and the keys have passed the test below.', 'qevix-shield' ); ?></p>
				<?php
				// Keys are present but unproven. Two shapes: still OFF (saving with
				// the box ticked will leave it off), or already ON but the saved
				// trio no longer matches the tested one (e.g. the Version moved to
				// v3 after a v2 test) — in which case reCAPTCHA is INACTIVE at run
				// time and no form is protected until it is re-tested. Say which.
				if ( $hasKeys && ! $isVerified ) {
					QevixShield_Menu::dependency_notice(
						$enabled
							? __( 'reCAPTCHA is switched on but currently <strong>inactive — no forms are protected</strong>. The saved Site Key, Version and Secret have not passed the key test (this happens when the Version is changed after testing, e.g. to v3 while the stored key is a v2 key). Press <strong>Test keys</strong> below and, once it passes, save again. Until then login stays open rather than locking everyone out over a config that cannot mint a token.', 'qevix-shield' )
							: __( 'These keys have not passed the key test yet, so reCAPTCHA cannot be turned on. Press <strong>Test keys</strong> below first. This guard exists because keys of the wrong type (v2 pasted where v3 is selected, or the reverse) stop the login form from working for everyone — including you.', 'qevix-shield' )
					);
				}

				if ( $enabled ) {
					$rcMissing = array();
					if ( '' === trim( $siteKey ) ) {
						$rcMissing[] = __( 'Site Key', 'qevix-shield' );
					}
					if ( ! $secretSaved ) {
						$rcMissing[] = __( 'Secret Key', 'qevix-shield' );
					}
					if ( ! empty( $rcMissing ) ) {
						QevixShield_Menu::dependency_notice( sprintf(
							/* translators: %s: comma-separated list of missing reCAPTCHA key fields */
							__( 'reCAPTCHA is on but the %s below is not set — it stays inactive and no form is protected until both keys are filled in. Get them from the Google reCAPTCHA admin console.', 'qevix-shield' ),
							'<strong>' . esc_html( implode( ' + ', $rcMissing ) ) . '</strong>'
						) );
					}
				}

				// Format sanity check (no call to Google): a stored key that does
				// not look like a reCAPTCHA key is almost always a mis-paste.
				// Shown whenever a malformed key is stored, even if the master
				// switch is off. It cannot detect a v2-vs-v3 mismatch (that only
				// shows when the widget renders), so it reminds the admin the key
				// type must match the selected Version. Non-blocking.
				$secretVal = (string) $settings->get( 'recaptcha_secret_key', '' );
				$badKeys   = array();
				if ( '' !== trim( $siteKey ) && ! QevixShield_Recaptcha::looks_like_key( $siteKey ) ) {
					$badKeys[] = __( 'Site Key', 'qevix-shield' );
				}
				if ( '' !== trim( $secretVal ) && ! QevixShield_Recaptcha::looks_like_key( $secretVal ) ) {
					$badKeys[] = __( 'Secret Key', 'qevix-shield' );
				}
				if ( ! empty( $badKeys ) ) {
					QevixShield_Menu::dependency_notice( sprintf(
						/* translators: %s: comma-separated list of reCAPTCHA key fields */
						__( 'The %s below does not look like a Google reCAPTCHA key (they start with <code>6L</code> and are about 40 characters) — double-check you pasted the whole key. Also note v2 and v3 keys are not interchangeable: the key type must match the Version selected above.', 'qevix-shield' ),
						'<strong>' . esc_html( implode( ' + ', $badKeys ) ) . '</strong>'
					) );
				}
				?>
			</td>
		</tr>

		<tr>
			<th scope="row"><?php esc_html_e( 'reCAPTCHA Version', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( '<strong>v2</strong> shows the familiar "I\'m not a robot" checkbox. <strong>v3</strong> is invisible — Google scores each request in the background and the score threshold below decides. Pick whichever type your keys were created as; the two are not interchangeable.', 'qevix-shield' ) ); ?>
				<p><label><input type="radio" name="recaptcha_version" value="v2" <?php checked( 'v2', $version ); ?> /> <?php esc_html_e( 'v2 — the visible "I\'m not a robot" checkbox on each protected form.', 'qevix-shield' ); ?></label></p>
				<p><label><input type="radio" name="recaptcha_version" value="v3" <?php checked( 'v3', $version ); ?> /> <?php esc_html_e( 'v3 — invisible, score-based. No checkbox; visitors only see the small reCAPTCHA badge in the page corner.', 'qevix-shield' ); ?></label></p>
				<p class="description"><?php esc_html_e( 'Must match the type you picked when creating your keys — v2 keys do not work with v3 and vice versa. Changing this clears the key test, so re-test before switching protection back on.', 'qevix-shield' ); ?></p>
			</td>
		</tr>

		<tr>
			<th scope="row"><label for="recaptcha_site_key"><?php esc_html_e( 'Site Key', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'The public key from your Google reCAPTCHA admin console — it is embedded in the login page HTML so browsers can request a token. Safe to be visible; it only works on the domains you registered.', 'qevix-shield' ) ); ?>
				<input type="text" name="recaptcha_site_key" id="recaptcha_site_key" class="regular-text" value="<?php echo esc_attr( $siteKey ); ?>" />
				<br />
				<a class="qevix-shield-external-link" href="https://www.google.com/recaptcha/admin/create" target="_blank" rel="noopener">
					<?php esc_html_e( 'Need help? Get your free keys from the Google reCAPTCHA console', 'qevix-shield' ); ?>
					<span class="dashicons dashicons-external" aria-hidden="true"></span>
				</a>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="recaptcha_secret_key"><?php esc_html_e( 'Secret Key', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'The private key from the same console page. The server uses it to verify tokens with Google — keep it secret; anyone holding it could forge "human" verdicts for your site.', 'qevix-shield' ) ); ?>
				<input type="password" name="recaptcha_secret_key" id="recaptcha_secret_key" class="regular-text" value="" autocomplete="new-password" placeholder="<?php echo $secretSaved ? esc_attr__( '••••••• (saved — leave blank to keep)', 'qevix-shield' ) : ''; ?>" />
				<p class="description"><?php esc_html_e( 'Stored securely and never shown again — the field stays blank on purpose. Leave it blank to keep the saved key, or type a new one to replace it.', 'qevix-shield' ); ?></p>
			</td>
		</tr>

		<tr>
			<th scope="row"><?php esc_html_e( 'Test Keys', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Runs the real reCAPTCHA check right here, using the <strong>saved</strong> keys and version, and asks Google to verify the result. It proves the keys are valid, that they match the saved version, and that the secret belongs to the same pair — <strong>before</strong> the login form depends on them. Save your changes first, then test; reCAPTCHA cannot be switched on until the test passes.', 'qevix-shield' ) ); ?>
				<button type="button" class="button" id="qevix-shield-rc-test"><?php esc_html_e( 'Test keys', 'qevix-shield' ); ?></button>

				<?php if ( $isVerified ) : ?>
					<span class="qevix-shield-rc-verified">
						<span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
						<?php
						printf(
							/* translators: %s: reCAPTCHA version (v2/v3) */
							esc_html__( 'These keys are verified for %s.', 'qevix-shield' ),
							esc_html( $version )
						);
						?>
					</span>
				<?php endif; ?>

				<p id="qevix-shield-rc-test-result" class="qevix-shield-rc-result" role="status" aria-live="polite"></p>

				<?php // v2 renders the real checkbox here for the admin to tick; v3 is automatic. ?>
				<div id="qevix-shield-rc-test-widget" hidden></div>

				<p class="description">
					<?php esc_html_e( 'Save your keys and version first — the test checks what is saved, so paste the keys, press Save, then press Test keys. Each combination has to prove itself: changing the keys or the version clears the result and locks the switch again until you save and re-test.', 'qevix-shield' ); ?>
				</p>
			</td>
		</tr>

			<tr>
				<th scope="row"><label for="recaptcha_threshold"><?php esc_html_e( 'Score Threshold', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'v3 only. Google rates each request from 0.0 (certainly a bot) to 1.0 (certainly human); anything scoring BELOW this value is rejected. <code>0.5</code> is the usual starting point.', 'qevix-shield' ) ); ?>
					<input type="number" class="qevix-shield-num-input" step="0.1" min="0" max="1" name="recaptcha_threshold" id="recaptcha_threshold" value="<?php echo esc_attr( $threshold ); ?>" />
					<p class="description"><?php esc_html_e( 'v3 only. Requests scoring below this (0.0 = likely bot, 1.0 = likely human) are blocked. 0.5 is a common default. Ignored for v2.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Email Verification Fallback', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'v3 only. The score check sometimes misjudges a real person — VPNs, strict privacy browsers, and shared networks all lower the score. With this on, a rejected sign-in emails the account holder a one-time verification link (valid 15 minutes): opening it lets them log in past the bot check once, <strong>with their password — and 2FA — still required</strong>. Bots gain nothing: the on-screen response is identical whether or not the username exists, and the link only ever goes to the account\'s own mailbox.', 'qevix-shield' ) ); ?>
					<?php $rcEmailFallback = (bool) $settings->get( 'recaptcha_email_fallback', false ); ?>
					<label><input type="checkbox" name="recaptcha_email_fallback" value="1" <?php checked( $rcEmailFallback ); ?> /> <?php esc_html_e( 'Email a one-time sign-in verification link when the score check rejects a login', 'qevix-shield' ); ?></label>
					<p class="description"><?php esc_html_e( 'Applies to the Login form when Version is v3. At most one email per account every 10 minutes.', 'qevix-shield' ); ?></p>
				</td>
			</tr>

		<tr>
			<th scope="row"><?php esc_html_e( 'Protect Forms', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Which forms get the check. <strong>Login</strong> stops credential-stuffing, <strong>Registration</strong> stops fake account floods, <strong>Lost Password</strong> stops reset-email spam. Leave Login ticked as the baseline.', 'qevix-shield' ) ); ?>
				<?php
				$savedForms = (array) $settings->get( 'recaptcha_forms', array( 'login' ) );
				$choices    = array(
					'login'        => __( 'Login', 'qevix-shield' ),
					'register'     => __( 'Registration', 'qevix-shield' ),
					'lostpassword' => __( 'Lost Password', 'qevix-shield' ),
				);
				foreach ( $choices as $value => $label ) :
					$checked = in_array( $value, $savedForms, true );
					?>
					<label class="qevix-shield-choice"><input type="checkbox" name="recaptcha_forms[]" value="<?php echo esc_attr( $value ); ?>" <?php checked( $checked ); ?> /> <?php echo esc_html( $label ); ?></label>
				<?php endforeach; ?>
				<p class="description">
					<?php if ( $isPro ) : ?>
						<?php esc_html_e( 'Each checked form gets the check on wp-login.php and, when WooCommerce is active, on the matching my-account/checkout form too.', 'qevix-shield' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Each checked form gets the check on wp-login.php. Unticking every box falls back to Login.', 'qevix-shield' ); ?>
					<?php endif; ?>
				</p>
			</td>
		</tr>
	</table>

	<?php $siteDomain = (string) wp_parse_url( home_url(), PHP_URL_HOST ); ?>
	<details class="qevix-shield-guide">
		<summary><span class="dashicons dashicons-editor-help" aria-hidden="true"></span> <?php esc_html_e( 'New to reCAPTCHA? Step-by-step: getting your Site Key and Secret Key', 'qevix-shield' ); ?></summary>
		<div class="qevix-shield-guide-body">
			<p><?php esc_html_e( 'The keys are free and take about two minutes to create. You only need a Google account (the same one used for Gmail works).', 'qevix-shield' ); ?></p>
			<ol>
				<li>
					<?php esc_html_e( 'Open the Google reCAPTCHA console (opens in a new tab) and sign in with your Google account:', 'qevix-shield' ); ?>
					<br />
					<a href="https://www.google.com/recaptcha/admin/create" target="_blank" rel="noopener">https://www.google.com/recaptcha/admin/create <span class="dashicons dashicons-external" aria-hidden="true"></span></a>
				</li>
				<li><?php esc_html_e( 'Label: any name you like, e.g. your site name.', 'qevix-shield' ); ?></li>
				<li><?php esc_html_e( 'reCAPTCHA type: pick the SAME version you selected above — "Score based (v3)" or "Challenge (v2) → I\'m not a robot Checkbox". Keys of one type do not work with the other.', 'qevix-shield' ); ?></li>
				<li>
					<?php
					printf(
						/* translators: %s: this site's domain */
						esc_html__( 'Domains: enter this site\'s domain exactly: %s (no https:// and no trailing slash).', 'qevix-shield' ),
						'<code>' . esc_html( $siteDomain ) . '</code>'
					);
					?>
				</li>
				<li><?php esc_html_e( 'Accept the terms and press Submit. Google then shows two long codes: the SITE KEY and the SECRET KEY.', 'qevix-shield' ); ?></li>
				<li><?php esc_html_e( 'Copy each code into its matching field above and press Save (leave "Enable reCAPTCHA" unticked for now).', 'qevix-shield' ); ?></li>
				<li><?php esc_html_e( 'Press "Test keys". This checks the saved keys against Google right here — reCAPTCHA will not switch on until it passes, so a wrong key type cannot lock you out of your own login form.', 'qevix-shield' ); ?></li>
				<li><?php esc_html_e( 'Once the test passes, tick "Enable reCAPTCHA" and press Save again. Then open your login page in a private/incognito window to confirm it works before logging out here.', 'qevix-shield' ); ?></li>
			</ol>
		</div>
	</details>

	<?php submit_button( __( 'Save reCAPTCHA Settings', 'qevix-shield' ) ); ?>
</form>

<?php if ( ! $isPro ) : ?>
	<?php
	// Sessions-style upsell card (bullet list + the two standard CTAs), matching
	// "Advanced Login Protection — Pro" — not a disabled-settings preview.
	QevixShield_Menu::render_pro_upsell(
		__( 'reCAPTCHA', 'qevix-shield' ),
		__( 'Everything above — v2 and v3, the score threshold, the email fallback and all three login forms — is included here and always will be. Qevix Shield Pro extends the check to forms this plugin does not itself render:', 'qevix-shield' ),
		array(
			__( 'The WooCommerce my-account and checkout forms (login, registration, lost-password)', 'qevix-shield' ),
			__( 'Bridge hooks to drop the check into any other plugin\'s custom login or registration form', 'qevix-shield' ),
		)
	);
	?>
<?php endif; ?>
