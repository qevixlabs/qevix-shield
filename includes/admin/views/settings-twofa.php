<?php
/**
 * Two-Factor Auth tab (free-owned, single-form pattern). Policy section (admins)
 * + per-user enrollment. Expects: $userId, $masterOn, $enabled, $isPro,
 * $pendingSecret, $otpauthUri, $recoveryNew, $proValues, $settings.
 *
 * FREE tier: "Enable 2FA" is editable; "Enforce for roles" is LOCKED to
 * Administrator (checked + disabled, others disabled, lock icon in the label)
 * and forces admins only. All-role enforcement, "Trust device for (days)" and
 * "Email fallback" are advertised in the "Two-Factor Auth — Pro" bullet card
 * (QevixShield_Menu::render_pro_upsell) rendered at the BOTTOM, after the
 * authenticator setup section. When the pro plugin is active the roles row plus
 * the trusted-days / email-fallback rows render editable inline (lock icon + Pro
 * card disappear) and pro persists them via the qevix_shield_twofa_save_pro action.
 *
 * Base 2FA (setup/enrollment, the login challenge, recovery codes, admin reset)
 * works with no license. Setup is opt-in and ALWAYS available — it is not gated
 * on the "Enable 2FA" master, which only governs FORCED enrollment.
 *
 * Help text adapts to $isPro so it is accurate both standalone and with pro.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$showPolicy = current_user_can( 'manage_options' );
?>
	<?php // Tab heading + subtext render for every viewer (standing heading rule). ?>
	<h3><?php esc_html_e( 'Two-Factor Auth', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Require a 6-digit code from an authenticator app alongside the password. Each user enrols on this tab; administrators set the site-wide policy.', 'qevix-shield' ); ?></p>

	<?php if ( $showPolicy ) : ?>
		<?php if ( isset( $_GET['policy_saved'] ) ) : ?>
			<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Two-Factor Auth settings saved.', 'qevix-shield' ); ?></p></div>
		<?php endif; ?>
		<?php if ( QevixShield_TwoFA::is_bypassed() ) : ?>
			<div class="notice notice-warning"><p>
				<?php esc_html_e( 'Two-factor enforcement is suspended by a wp-config.php constant (Safe Mode or a disable switch — an emergency bypass to recover from a lockout). The policy below is saved but not enforced — no login challenge or forced enrollment runs — until that line is removed.', 'qevix-shield' ); ?>
			</p></div>
		<?php endif; ?>
		<div class="qevix-shield-section">
			<h3><?php esc_html_e( 'Policy (site-wide)', 'qevix-shield' ); ?></h3>
			<p class="description"><?php esc_html_e( 'Administrator settings that apply to every account on this site.', 'qevix-shield' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'qevix_shield_2fa_policy' ); ?>
				<input type="hidden" name="action" value="qevix_shield_2fa_policy" />
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Require 2FA', 'qevix-shield' ); ?></th>
						<td><?php QevixShield_Menu::help_tip( __( 'When on, users in the enforced roles below <strong>must</strong> set up two-factor authentication before they can use the dashboard. Leaving it off does not disable 2FA: any user can still turn it on for their own account below at any time, and once enrolled they are always asked for the 6-digit code at login. This switch only controls whether it is <em>mandatory</em> for the roles below.', 'qevix-shield' ) ); ?><label><input type="checkbox" name="twofa_enabled" value="1" <?php checked( (bool) $masterOn ); ?> /> <?php esc_html_e( 'Require the enforced roles below to set up two-factor authentication', 'qevix-shield' ); ?></label>
						<p class="description"><?php esc_html_e( 'Setting up 2FA stays optional for everyone else — enrolled users are always asked for their code at login, whether or not this is on.', 'qevix-shield' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row">
							<?php esc_html_e( 'Enforce for roles', 'qevix-shield' ); ?>
						</th>
						<td><?php QevixShield_Menu::help_tip( __( 'Makes 2FA mandatory for the ticked roles: after logging in, a user in that role sees only the 2FA setup screen until they enrol. Tick every role that must use two-factor. Unticking everything falls back to Administrator.', 'qevix-shield' ) ); ?>
							<?php $enforced = (array) $settings->get( 'twofa_enforced_roles', array( 'administrator' ) ); ?>
							<div class="qevix-shield-choices">
								<?php foreach ( wp_roles()->get_names() as $roleKey => $roleLabel ) : ?>
									<?php
									$checked = in_array( $roleKey, $enforced, true );
									?>
									<label><input type="checkbox" name="twofa_enforced_roles[]" value="<?php echo esc_attr( $roleKey ); ?>" <?php checked( $checked ); ?> /> <?php echo esc_html( translate_user_role( $roleLabel ) ); ?></label>
								<?php endforeach; ?>
							</div>
							<p class="description">
								<?php esc_html_e( 'After logging in, users in a checked role who have not enrolled see only a standalone 2FA setup screen — no admin pages or menu — until they enrol.', 'qevix-shield' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="twofa_xmlrpc_mode"><?php esc_html_e( 'XML-RPC logins', 'qevix-shield' ); ?></label></th>
						<td><?php QevixShield_Menu::help_tip( __( 'XML-RPC (used by some older apps and publishing tools) accepts a plain username and password with <strong>no second factor</strong> — WordPress\'s default leaves it as a side door around 2FA. "Require the code" keeps those clients working: the user appends the current 6-digit code (or a recovery code) to the end of the password, e.g. <code>mypassword123456</code>. "Block" refuses XML-RPC password sign-ins for enrolled accounts entirely. Application passwords are never affected — each one is its own revocable credential.', 'qevix-shield' ) ); ?>
							<select name="twofa_xmlrpc_mode" id="twofa_xmlrpc_mode">
								<option value="allow" <?php selected( $xmlrpcMode, 'allow' ); ?>><?php esc_html_e( 'Allow without a code (WordPress default)', 'qevix-shield' ); ?></option>
								<option value="code" <?php selected( $xmlrpcMode, 'code' ); ?>><?php esc_html_e( 'Require the 2FA code appended to the password', 'qevix-shield' ); ?></option>
								<option value="block" <?php selected( $xmlrpcMode, 'block' ); ?>><?php esc_html_e( 'Block XML-RPC password logins for 2FA accounts', 'qevix-shield' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Applies only to accounts that have set up 2FA. Tip: if nothing on your site uses XML-RPC, disabling it entirely on the XML-RPC tab is the strongest option.', 'qevix-shield' ); ?></p>
						</td>
					</tr>
					<?php if ( $isPro ) : ?>
						<tr>
							<th scope="row"><label for="twofa_trusted_days"><?php esc_html_e( 'Trust device for (days)', 'qevix-shield' ); ?></label></th>
							<td><?php QevixShield_Menu::help_tip( __( 'After a successful code entry the user can tick "trust this device", and that browser skips the code prompt for this many days — e.g. <code>30</code> means one code per month on your own computer, while every new/unknown device still gets challenged.', 'qevix-shield' ) ); ?><input type="number" class="qevix-shield-num-input" min="1" name="twofa_trusted_days" id="twofa_trusted_days" value="<?php echo esc_attr( (int) ( $proValues['twofa_trusted_days'] ?? 30 ) ); ?>" /></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Email fallback', 'qevix-shield' ); ?></th>
							<td><?php QevixShield_Menu::help_tip( __( 'Rescue path for a lost or dead phone: the login screen offers to email a one-time code to the account\'s address instead. Convenient, but it means 2FA is only as strong as the user\'s mailbox — disable it for maximum strictness (recovery codes still work).', 'qevix-shield' ) ); ?><label><input type="checkbox" name="twofa_email_fallback" value="1" <?php checked( ! empty( $proValues['twofa_email_fallback'] ) ); ?> /> <?php esc_html_e( 'Allow a one-time emailed code when the authenticator app is unavailable', 'qevix-shield' ); ?></label></td>
						</tr>
					<?php endif; ?>
				</table>
				<?php submit_button( __( 'Save Policy', 'qevix-shield' ) ); ?>
			</form>
		</div>
	<?php endif; ?>

	<?php
	// ----------------------------- enrollment ------------------------------
	// Setup is always available (opt-in, no site-wide-switch restriction): any
	// logged-in user can enrol their authenticator here, and once enrolled they
	// are challenged at login whether or not the "Enable 2FA" policy is on.
	?>

	<?php if ( isset( $_GET['enroll_error'] ) ) : ?>
		<div class="notice notice-error"><p><?php esc_html_e( 'That verification code did not match. Enter the current 6-digit code shown in your authenticator app (and check that your device clock is set to automatic), then try again.', 'qevix-shield' ); ?></p></div>
	<?php endif; ?>

	<?php if ( ! empty( $recoveryNew ) ) : ?>
		<div class="notice notice-success qevix-shield-notice-box">
			<h2><?php esc_html_e( 'Save your recovery codes', 'qevix-shield' ); ?></h2>
			<p><?php esc_html_e( 'Each code works once if you lose access to your authenticator. Store them somewhere safe — they will not be shown again.', 'qevix-shield' ); ?></p>
			<pre class="qevix-shield-2fa-codes"><?php echo esc_html( implode( "\n", $recoveryNew ) ); ?></pre>
			<?php
			// Downloadable copy of the codes (data: URI — the codes are already in
			// this page's markup, so no extra endpoint or JS library is needed).
			$recoveryFile  = sprintf(
				/* translators: 1: site URL, 2: username. */
				__( 'Two-factor authentication recovery codes — %1$s (%2$s)', 'qevix-shield' ),
				home_url(),
				$account
			) . "\r\n";
			$recoveryFile .= sprintf(
				/* translators: %s: date. */
				__( 'Generated: %s', 'qevix-shield' ),
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) )
			) . "\r\n\r\n";
			$recoveryFile .= __( 'Each line is a one-time recovery code. If you lose access to your authenticator app, enter one of these codes at the login 2FA prompt instead of the 6-digit code. Each code works only once.', 'qevix-shield' ) . "\r\n\r\n";
			$recoveryFile .= implode( "\r\n", $recoveryNew ) . "\r\n";
			$recoveryName  = sanitize_file_name( 'recovery-codes-' . wp_parse_url( home_url(), PHP_URL_HOST ) . '.txt' );
			?>
			<p>
				<a class="button button-secondary" download="<?php echo esc_attr( $recoveryName ); ?>" href="data:text/plain;charset=utf-8,<?php echo esc_attr( rawurlencode( $recoveryFile ) ); ?>">
					<span class="dashicons dashicons-download qevix-shield-btn-icon"></span><?php esc_html_e( 'Download Codes', 'qevix-shield' ); ?>
				</a>
			</p>
		</div>
	<?php endif; ?>

	<?php if ( $enabled ) : ?>

		<div>
			<h3><?php esc_html_e( 'Your two-factor authentication', 'qevix-shield' ); ?></h3>
			<p class="description"><?php esc_html_e( 'Manage the second factor on your own account.', 'qevix-shield' ); ?></p>
			<p><span class="dashicons dashicons-yes-alt qevix-shield-text-good"></span> <strong><?php esc_html_e( 'Your authenticator app is set up on this account.', 'qevix-shield' ); ?></strong></p>
			<p class="description"><?php esc_html_e( 'Each time you sign in, you will be asked for the current 6-digit code from your authenticator app.', 'qevix-shield' ); ?></p>

			<div class="qevix-shield-action-row">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'qevix_shield_2fa_recovery' ); ?>
					<input type="hidden" name="action" value="qevix_shield_2fa_recovery" />
					<?php submit_button( __( 'Regenerate Recovery Codes', 'qevix-shield' ), 'secondary', 'submit', false ); ?>
				</form>

				<?php
				/**
				 * Pro renders its "Revoke Trusted Devices" button here (trusted
				 * devices are a pro feature; the action is registered by pro).
				 */
				do_action( 'qevix_shield_2fa_account_actions', $userId );
				?>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Disable two-factor authentication for your account?', 'qevix-shield' ) ); ?>');">
					<?php wp_nonce_field( 'qevix_shield_2fa_disable' ); ?>
					<input type="hidden" name="action" value="qevix_shield_2fa_disable" />
					<?php submit_button( __( 'Disable 2FA', 'qevix-shield' ), 'delete', 'submit', false ); ?>
				</form>
			</div>
		</div>

	<?php else : ?>

		<div>
			<h3><?php esc_html_e( 'Set up your authenticator app', 'qevix-shield' ); ?></h3>
			<p class="description"><?php esc_html_e( 'Scan the QR code with an authenticator app, then confirm with the 6-digit code it shows.', 'qevix-shield' ); ?></p>

			<details class="qevix-shield-guide">
				<summary><span class="dashicons dashicons-editor-help" aria-hidden="true"></span> <?php esc_html_e( 'Need help? What this is and how to set it up (first-time guide)', 'qevix-shield' ); ?></summary>
				<div class="qevix-shield-guide-body">
					<p><?php esc_html_e( 'Two-factor authentication (2FA) adds a second lock to your account: besides your password, logging in also asks for a 6-digit code that only YOUR phone can produce. Even someone who steals your password cannot get in without your phone.', 'qevix-shield' ); ?></p>
					<p><strong><?php esc_html_e( 'Step 1 — install a free authenticator app on your phone (any one of these):', 'qevix-shield' ); ?></strong></p>
					<ul class="qevix-shield-app-links">
						<li><a href="https://apps.apple.com/app/google-authenticator/id388497605" target="_blank" rel="noopener"><?php esc_html_e( 'Google Authenticator — iPhone', 'qevix-shield' ); ?> <span class="dashicons dashicons-external" aria-hidden="true"></span></a></li>
						<li><a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank" rel="noopener"><?php esc_html_e( 'Google Authenticator — Android', 'qevix-shield' ); ?> <span class="dashicons dashicons-external" aria-hidden="true"></span></a></li>
						<li><a href="https://www.microsoft.com/en-us/security/mobile-authenticator-app" target="_blank" rel="noopener"><?php esc_html_e( 'Microsoft Authenticator', 'qevix-shield' ); ?> <span class="dashicons dashicons-external" aria-hidden="true"></span></a></li>
						<li><a href="https://authy.com/download/" target="_blank" rel="noopener"><?php esc_html_e( 'Authy (phone + desktop)', 'qevix-shield' ); ?> <span class="dashicons dashicons-external" aria-hidden="true"></span></a></li>
					</ul>
					<p><strong><?php esc_html_e( 'Step 2 — connect it to this site:', 'qevix-shield' ); ?></strong> <?php esc_html_e( 'open the app, tap "+" / "Add account" / "Scan QR code", and point the phone camera at the QR code below. The app immediately starts showing a 6-digit code that changes every 30 seconds — type the current one into the confirmation box to finish.', 'qevix-shield' ); ?></p>
					<p><?php esc_html_e( 'Tip: afterwards you will get one-time recovery codes — save them somewhere safe (password manager, printed note). They are your way in if you ever lose the phone.', 'qevix-shield' ); ?></p>
				</div>
			</details>

			<ol>
				<li><?php esc_html_e( 'Scan this QR code with Google Authenticator, Authy, 1Password, Bitwarden, or FreeOTP.', 'qevix-shield' ); ?></li>
				<li><?php esc_html_e( 'Or enter the key manually.', 'qevix-shield' ); ?></li>
				<li><?php esc_html_e( 'Then type the 6-digit code the app shows to confirm.', 'qevix-shield' ); ?></li>
			</ol>

			<div id="qevix-shield-2fa-qr" class="qevix-shield-2fa-qr"></div>
			<?php
			// Hand the otpauth URI to the enqueued QR renderer (qevix-shield-twofa-qr,
			// registered in QevixShield_TwoFA::enqueue_assets) instead of an inline
			// <script> tag.
			wp_add_inline_script(
				'qevix-shield-twofa-qr',
				'window.QevixShield2FAQR = ' . wp_json_encode( array( 'otpauth' => $otpauthUri ) ) . ';',
				'before'
			);
			?>

			<p><?php esc_html_e( 'Manual entry key:', 'qevix-shield' ); ?> <code class="qevix-shield-2fa-key"><?php echo esc_html( $pendingSecret ); ?></code></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'qevix_shield_2fa_enroll' ); ?>
				<input type="hidden" name="action" value="qevix_shield_2fa_enroll" />
				<p>
					<label for="qevix_shield_2fa_code"><strong><?php esc_html_e( 'Verification code', 'qevix-shield' ); ?></strong></label><br />
					<input type="text" inputmode="numeric" pattern="[0-9]*" name="qevix_shield_2fa_code" id="qevix_shield_2fa_code" class="regular-text" autocomplete="one-time-code" placeholder="123456" />
				</p>
				<?php submit_button( __( 'Verify & Activate', 'qevix-shield' ) ); ?>
			</form>
		</div>

	<?php endif; ?>

	<?php if ( $showPolicy && ! $isPro ) : ?>
		<?php
		// Sessions-style upsell card (bullet list + the two standard CTAs),
		// matching "Advanced Login Protection — Pro" — placed at the BOTTOM, after
		// the authenticator setup section (admins only).
		QevixShield_Menu::render_pro_upsell(
			__( 'Two-Factor Auth', 'qevix-shield' ),
			__( 'Two-factor authentication is fully included here — enrolment, recovery codes, admin reset and per-role enforcement. Qevix Shield Pro adds convenience on top:', 'qevix-shield' ),
			array(
				__( 'Trusted devices — skip the code on browsers you approve for a number of days', 'qevix-shield' ),
				__( 'One-time emailed code fallback when the authenticator app is unavailable', 'qevix-shield' ),
			)
		);
		?>
	<?php endif; ?>
<?php
