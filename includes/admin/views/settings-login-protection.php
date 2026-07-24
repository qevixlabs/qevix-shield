<?php
/**
 * Login Protection settings section (form only — no page chrome; shared by the
 * standalone submenu page and the Settings > Login Protection tab). Expects
 * $settings.
 *
 * ONE form, ONE save button. The pro "Advanced Login Protection" fields sit in
 * the SAME form, and what renders depends on the license:
 *
 *   - Unlicensed: no pro fields at all — `QevixShield_Menu::render_pro_upsell()`
 *     draws a card listing what Pro adds here, with the two standard CTAs.
 *     Nothing inert or greyed out is shown in place of the fields.
 *   - Licensed, but the viewer lacks manage_options (pro settings stay
 *     manage_options-only by design): the real fields render read-only inside
 *     a bordered `<fieldset disabled>` with a lock-icon legend — a preview of
 *     settings that exist, not of settings that must be bought.
 *   - Licensed AND the viewer is an admin: the fields render as a plain
 *     section (same look as the free fields above, e.g. IP Whitelist), values
 *     filled by pro through `qevix_shield_login_protection_pro_values`. The
 *     single Save button persists both halves (free keys via free's handler,
 *     pro keys via its `qevix_shield_login_protection_save_pro` listener).
 *
 * Free's save handler never persists the pro keys in any case; it only fires
 * `qevix_shield_login_protection_save_pro`, which has no listener unless a
 * licensed pro plugin is installed.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$isPro  = (bool) apply_filters( 'qevix_shield_is_pro_active', false );

// Pro settings are admin-only by design (see access-control notes): a
// non-admin who was granted the Qevix Shield capability still sees the pro
// fields read-only.
$proEditable = $isPro && current_user_can( 'manage_options' );

/**
 * Display values for the pro fields. Free ships the defaults so the locked
 * preview always renders; the pro plugin overlays its saved values when
 * licensed.
 */
$proValues = (array) apply_filters(
	'qevix_shield_login_protection_pro_values',
	array(
		'block_permanent_after_lockouts' => 0,
		'ip_blacklist'                   => '',
		'ua_blocklist'                   => '',
		'whitelist_cidr'                 => '',
	)
);
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="login-protection" />

	<?php $loginProtectionOn = (bool) $settings->get( 'login_protection_enabled', false ); ?>
	<h3><?php esc_html_e( 'Login Protection', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Stop bots and brute-force attacks at the login form with a honeypot, rate limiting, and temporary IP lockouts.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Login Protection', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Master switch for this whole tab. While OFF, none of the settings below act — no honeypot, no rate limiting — so you can configure them first and switch protection on when ready. Turn it ON to activate whatever you have enabled below.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="login_protection_enabled" value="1" <?php checked( $loginProtectionOn ); ?> /> <?php esc_html_e( 'Enable login protection (the settings below act only when this is on)', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default — the honeypot and rate limiting below stay inactive until you enable this.', 'qevix-shield' ); ?></p>
				<?php
				if ( ! $loginProtectionOn && ( $settings->get( 'honeypot_enabled', false ) || $settings->get( 'rate_limit_enabled', false ) ) ) {
					QevixShield_Menu::dependency_notice( __( 'You have options enabled below, but Login Protection is <strong>off</strong> — they are saved as a draft and do nothing until you turn this on.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Honeypot Field', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Adds an invisible extra field to the login form. Humans never see it, but automated bots fill in every field they find — any login attempt that fills the hidden field is rejected as a bot. No effect on real visitors; safe to leave on.', 'qevix-shield' ) ); ?><label><input type="checkbox" name="honeypot_enabled" value="1" <?php checked( $settings->get( 'honeypot_enabled', false ) ); ?> /> <?php esc_html_e( 'Enable hidden honeypot field on login form', 'qevix-shield' ); ?></label></td>
		</tr>
		<tr>
			<th scope="row"><label for="ip_whitelist"><?php esc_html_e( 'IP Whitelist', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Trusted addresses that can never be rate-limited or locked out — add your own static IP (search "what is my IP") or your office address so you cannot lock yourself out while testing. Example: <code>203.0.113.5</code>, one per line. Do not add addresses you do not control.', 'qevix-shield' ) ); ?>
				<textarea name="ip_whitelist" id="ip_whitelist" rows="4" class="large-text" placeholder="203.0.113.5"><?php echo esc_textarea( $settings->get( 'ip_whitelist', '' ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'One IP per line. These IPs never trigger rate limiting or lockout. Single addresses only — whole ranges (CIDR) are a Pro feature (Whitelist CIDR Ranges below); range entries here are ignored.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Rate Limiting', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Stops password-guessing (brute-force) attacks. Example with the defaults: 5 failed logins from the same IP within 15 minutes locks that IP out of the login page for 15 minutes, then access returns automatically. Lower "fails allowed" = stricter; raise the lockout duration to punish repeat offenders longer.', 'qevix-shield' ) ); ?>
				<p class="qevix-shield-field-row">
					<label><input type="checkbox" name="rate_limit_enabled" value="1" <?php checked( $settings->get( 'rate_limit_enabled', false ) ); ?> /> <?php esc_html_e( 'Enable rate limiting and temporary IP lockouts', 'qevix-shield' ); ?></label>
				</p>
				<p class="qevix-shield-field-row">
					<label>
						<input type="number" class="qevix-shield-num-input" min="1" name="rate_limit_fails" value="<?php echo esc_attr( $settings->get( 'rate_limit_fails', 5 ) ); ?>" />
						<?php esc_html_e( 'failed logins allowed before the IP is locked out', 'qevix-shield' ); ?>
					</label>
				</p>
				<p class="qevix-shield-field-row">
					<label>
						<input type="number" class="qevix-shield-num-input" min="1" name="rate_limit_window_minutes" value="<?php echo esc_attr( $settings->get( 'rate_limit_window_minutes', 15 ) ); ?>" />
						<?php esc_html_e( 'minutes in which those failures are counted', 'qevix-shield' ); ?>
					</label>
				</p>
				<p class="qevix-shield-field-row">
					<label>
						<input type="number" class="qevix-shield-num-input" min="1" name="lockout_duration_minutes" value="<?php echo esc_attr( $settings->get( 'lockout_duration_minutes', 15 ) ); ?>" />
						<?php esc_html_e( 'minutes the lockout lasts before access returns automatically', 'qevix-shield' ); ?>
					</label>
				</p>
				<p class="description"><?php esc_html_e( 'Example with the defaults: 5 failures within 15 minutes lock that IP out for 15 minutes.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
	</table>

	<?php
	// Lock badge rendered next to each paid field's label while those fields
	// are disabled; disappears once the license unlocks them.
	$proLock = $proEditable ? '' : '<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span> ';
	?>
	<?php if ( $isPro ) : ?>

	<?php if ( $proEditable ) : ?>
		<h3><?php esc_html_e( 'Advanced Login Protection', 'qevix-shield' ); ?></h3>
		<p class="description"><?php esc_html_e( 'Pro rules on top of the free protection above: permanent blacklists, user-agent filtering, and network-range whitelisting.', 'qevix-shield' ); ?></p>
	<?php else : ?>
		<fieldset class="qevix-shield-pro-fieldset" disabled>
			<legend>
				<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span>
				<?php esc_html_e( 'Advanced Login Protection (Pro)', 'qevix-shield' ); ?>
			</legend>
			<p class="description"><?php esc_html_e( 'These settings can only be changed by an administrator.', 'qevix-shield' ); ?></p>
	<?php endif; ?>

		<table class="form-table">
				<tr>
					<th scope="row"><label for="block_permanent_after_lockouts"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Permanent Block After N Lockouts', 'qevix-shield' ); ?></label></th>
					<td><?php QevixShield_Menu::help_tip( __( 'Escalates repeat offenders from temporary to permanent. Example: set to <code>3</code> — an IP that earns its third temporary lockout is added to the Permanent IP Blacklist below and stays blocked until you remove it. <code>0</code> disables the escalation.', 'qevix-shield' ) ); ?>
						<input type="number" class="qevix-shield-num-input" min="0" id="block_permanent_after_lockouts" name="block_permanent_after_lockouts" value="<?php echo esc_attr( $proValues['block_permanent_after_lockouts'] ); ?>" />
						<p class="description"><?php esc_html_e( 'Add an IP to the permanent blacklist automatically after this many temporary lockouts (0 = never).', 'qevix-shield' ); ?></p>
						<?php
						if ( (int) $proValues['block_permanent_after_lockouts'] > 0 && ! $settings->get( 'rate_limit_enabled', false ) ) {
							QevixShield_Menu::dependency_notice( __( 'This counts temporary lockouts, but <strong>Rate Limiting is off</strong> (above), so no lockouts ever happen and this never triggers. Enable rate limiting for it to take effect.', 'qevix-shield' ) );
						}
						?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="ip_blacklist"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Permanent IP Blacklist', 'qevix-shield' ); ?></label></th>
					<td><?php QevixShield_Menu::help_tip( __( 'Addresses banned from logging in until you delete them from this list. Accepts single IPs (<code>203.0.113.9</code>) or whole IPv4 ranges in CIDR form (<code>198.51.100.0/24</code> = all 256 addresses 198.51.100.0–255). Entries added automatically by the lockout escalation appear here too.', 'qevix-shield' ) ); ?>
						<textarea id="ip_blacklist" name="ip_blacklist" rows="4" class="large-text" placeholder="198.51.100.0/24"><?php echo esc_textarea( $proValues['ip_blacklist'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One IP or IPv4 CIDR range per line. These addresses are blocked before authentication and persist across lockout cycles.', 'qevix-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="ua_blocklist"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'User-Agent Filtering', 'qevix-shield' ); ?></label></th>
					<td><?php QevixShield_Menu::help_tip( __( 'Rejects login attempts by the browser identification string the client sends. Example: the line <code>curl</code> blocks any client whose user agent contains "curl"; the line <code>/^python/i</code> (wrapped in slashes) is a regular expression. Real browsers say things like "Mozilla/5.0 …" — avoid patterns that match those.', 'qevix-shield' ) ); ?>
						<textarea id="ua_blocklist" name="ua_blocklist" rows="4" class="large-text" placeholder="curl&#10;/sqlmap/i"><?php echo esc_textarea( $proValues['ua_blocklist'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One pattern per line. A pattern wrapped in /slashes/ is treated as a regular expression; anything else is a case-insensitive substring match. Matching requests are rejected before authentication.', 'qevix-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="whitelist_cidr"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Whitelist CIDR Ranges', 'qevix-shield' ); ?></label></th>
					<td><?php QevixShield_Menu::help_tip( __( 'Like the free IP Whitelist above, but for whole network ranges. Example: <code>10.0.0.0/8</code> exempts every address starting with 10. — typical for a company VPN or office network — from all rate limiting and blocking.', 'qevix-shield' ) ); ?>
						<textarea id="whitelist_cidr" name="whitelist_cidr" rows="3" class="large-text" placeholder="10.0.0.0/8"><?php echo esc_textarea( $proValues['whitelist_cidr'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'CIDR ranges that bypass all rate limiting and blocking (extends the free IP whitelist).', 'qevix-shield' ); ?></p>
					</td>
				</tr>
		</table>
	<?php if ( ! $proEditable ) : ?>
		</fieldset>
	<?php endif; ?>

	<?php endif; // $isPro ?>

	<?php submit_button( __( 'Save Changes', 'qevix-shield' ) ); ?>
</form>

<?php if ( ! $isPro ) : ?>
	<?php
	// The paid add-on's pitch sits BELOW the free form as a clearly separate
	// block — the free settings above are complete and save on their own.
	// Nothing here is a locked field.
	QevixShield_Menu::render_pro_upsell(
		__( 'Advanced Login Protection', 'qevix-shield' ),
		__( 'Qevix Shield Pro adds permanent, pattern-based blocking on top of the free rate limiting:', 'qevix-shield' ),
		array(
			__( 'Permanently blacklist attacker IPs — single addresses or whole CIDR ranges', 'qevix-shield' ),
			__( 'Auto-escalate repeat offenders to a permanent block after N temporary lockouts', 'qevix-shield' ),
			__( 'Reject login attempts by user-agent pattern (substring or regex)', 'qevix-shield' ),
			__( 'Whitelist entire network ranges (CIDR) for your office or VPN', 'qevix-shield' ),
		)
	);
	?>
<?php endif; ?>
