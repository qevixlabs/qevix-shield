<?php
/**
 * Password Security settings section (form only — no page chrome; shared by the
 * standalone submenu page and the Settings > Password Security tab). Expects
 * $settings.
 *
 * Single-form pattern (same as Login Protection): ONE settings form, ONE Save
 * button. The free fields (length + character classes,
 * disallow username/email) are always editable. The pro "Advanced Password
 * Security" fields sit in the SAME form: unlicensed shows the upsell card
 * (`QevixShield_Menu::render_pro_upsell`) instead of the fields — never an
 * inert copy of them; licensed non-admins get them read-only in a bordered
 * `<fieldset disabled>`; licensed admins get them plain and editable. Free
 * ships the display defaults via `qevix_shield_password_security_pro_values`;
 * the pro plugin overlays saved values and persists them on
 * `qevix_shield_password_security_save_pro`.
 *
 * "Force Password Reset" lives in this SAME form/Save button/pro
 * fieldset too, as a plain "Force Password Reset" h3 subsection (not a second
 * bordered box): Scope + a "Require Reset at Next Login" checkbox. It's a
 * one-shot ACTION, not a saved setting — clicking "Save Changes" also applies
 * it when the checkbox is checked (the box clears itself after each save,
 * like Malware Scanner's Run Scan trigger folded into a settings form). Free
 * never acts on it itself; pro's listener persists the Advanced Password
 * Security fields AND applies the force-reset from the same `$_POST`,
 * self-gated on `is_valid()` + `manage_options`.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$isPro       = (bool) apply_filters( 'qevix_shield_is_pro_active', false );
$proEditable = $isPro && current_user_can( 'manage_options' );

$proValues = (array) apply_filters(
	'qevix_shield_password_security_pro_values',
	array(
		'pwd_block_common'     => false,
		'pwd_block_breached'   => false,
		'pwd_expiry_days'      => 0,
		'pwd_expiry_warn_days' => 7,
		'pwd_history_count'    => 0,
	)
);

$expiryDays = (int) $proValues['pwd_expiry_days'];
$historyN   = (int) $proValues['pwd_history_count'];

// Preset options for the two selects; a value outside them becomes "Custom".
$expiryPresets  = array( 0, 30, 60, 90 );
$historyPresets = array( 0, 3, 5, 10 );
$expiryCustom   = ! in_array( $expiryDays, $expiryPresets, true );
$historyCustom  = ! in_array( $historyN, $historyPresets, true );

$forceResetNotice = (string) apply_filters( 'qevix_shield_password_force_reset_result', '' );

$proLock = $proEditable ? '' : '<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span> ';
?>
<?php if ( '' !== $forceResetNotice ) : ?>
	<div class="notice notice-success is-dismissible qevix-shield-narrow"><p><?php echo esc_html( $forceResetNotice ); ?></p></div>
<?php endif; ?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="password-security" />

	<?php
	$pwdPolicyOn = (bool) $settings->get( 'pwd_policy_enabled', false );
	// A password rule is "in effect" only if at least one concrete rule is set.
	$pwdHasRule  = (int) $settings->get( 'pwd_min_length', 8 ) > 0
		|| $settings->get( 'pwd_require_upper', false )
		|| $settings->get( 'pwd_require_lower', false )
		|| $settings->get( 'pwd_require_number', false )
		|| $settings->get( 'pwd_require_special', false )
		|| $settings->get( 'pwd_disallow_user_info', false );
	?>
	<h3><?php esc_html_e( 'Password Security', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Turn on password rules, then choose what to enforce when a password is set at registration, on the profile screen, and during password reset.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Password Rules', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Master switch for the length and character rules below (Minimum Length, Character Requirements, Personal Info). While OFF, none of them apply — WordPress behaves as stock. Turn it ON, then pick the rules. The Advanced Password Security section (Pro) has its own separate switches.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="pwd_policy_enabled" value="1" <?php checked( $pwdPolicyOn ); ?> /> <?php esc_html_e( 'Enforce the password rules below (length, character classes, personal info)', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default — these password requirements are not enforced until you enable this.', 'qevix-shield' ); ?></p>
				<?php
				if ( $pwdPolicyOn && ! $pwdHasRule ) {
					QevixShield_Menu::dependency_notice( __( 'Password rules are <strong>on</strong> but no rule is set — minimum length is 0 and every requirement is unchecked, so nothing is enforced. Set a minimum length or tick a requirement below.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="pwd_min_length"><?php esc_html_e( 'Minimum Length', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Shortest password a user may choose. Length matters more than symbols: each extra character multiplies the guesses an attacker needs. <code>0</code> enforces no minimum; <code>8</code> is a sensible floor and <code>12+</code> is the common recommendation for admin accounts. Only applies while Password Rules is on.', 'qevix-shield' ) ); ?>
				<input type="number" class="qevix-shield-num-input" min="0" max="256" id="pwd_min_length" name="pwd_min_length" value="<?php echo esc_attr( $settings->get( 'pwd_min_length', 8 ) ); ?>" />
				<p class="description"><?php esc_html_e( 'Minimum number of characters required in a password. 0 = no minimum length check.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Character Requirements', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Character classes every new password must contain. Example: with uppercase + number + special all required, <code>sunshine</code> is rejected but <code>Sunshine7!</code> passes. Applies when a password is SET (registration, profile, reset) — existing passwords are not retro-checked.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="pwd_require_upper" value="1" <?php checked( $settings->get( 'pwd_require_upper', true ) ); ?> /> <?php esc_html_e( 'Require an uppercase letter (A–Z)', 'qevix-shield' ); ?></label><br />
				<label><input type="checkbox" name="pwd_require_lower" value="1" <?php checked( $settings->get( 'pwd_require_lower', true ) ); ?> /> <?php esc_html_e( 'Require a lowercase letter (a–z)', 'qevix-shield' ); ?></label><br />
				<label><input type="checkbox" name="pwd_require_number" value="1" <?php checked( $settings->get( 'pwd_require_number', true ) ); ?> /> <?php esc_html_e( 'Require a number (0–9)', 'qevix-shield' ); ?></label><br />
				<label><input type="checkbox" name="pwd_require_special" value="1" <?php checked( $settings->get( 'pwd_require_special', false ) ); ?> /> <?php esc_html_e( 'Require a special character (!@#$…)', 'qevix-shield' ); ?></label>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Personal Info in Passwords', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Blocks the most-guessed passwords of all: the account\'s own details. Example: user <code>maria</code> (maria@example.com) could not choose <code>maria2024</code> or <code>Example.com1</code> — attackers always try these first.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="pwd_disallow_user_info" value="1" <?php checked( $settings->get( 'pwd_disallow_user_info', true ) ); ?> /> <?php esc_html_e( 'Disallow using the username or email address as (or inside) the password', 'qevix-shield' ); ?></label>
			</td>
		</tr>
	</table>

	<?php if ( $isPro ) : ?>

	<?php if ( $proEditable ) : ?>
	<h3><?php esc_html_e( 'Advanced Password Security', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Pro rules on top of the free policy above: breached-password blocking, expiration, and reuse prevention.', 'qevix-shield' ); ?></p>
	<?php else : ?>
	<fieldset class="qevix-shield-pro-fieldset" disabled>
		<legend>
			<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span>
			<?php esc_html_e( 'Advanced Password Security (Pro)', 'qevix-shield' ); ?>
		</legend>
		<p class="description"><?php esc_html_e( 'These settings can only be changed by an administrator.', 'qevix-shield' ); ?></p>
	<?php endif; ?>

		<table class="form-table">
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Block Common Passwords', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Rejects passwords that appear on a list of the most-used, already-leaked passwords — e.g. <code>password123</code>, <code>qwerty</code>, <code>iloveyou</code>. These are the first guesses in every automated attack, no matter how many character rules they satisfy.', 'qevix-shield' ) ); ?>
					<label><input type="checkbox" name="pwd_block_common" value="1" <?php checked( $proValues['pwd_block_common'] ); ?> /> <?php esc_html_e( 'Reject passwords found in the bundled common-password list', 'qevix-shield' ); ?></label>
					<p class="description"><?php esc_html_e( 'Checked at registration, profile update, and reset.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Block Breached Passwords', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Goes far beyond the bundled list: checks the candidate password against the public <strong>Have I Been Pwned</strong> database of over a billion passwords exposed in real data breaches. Privacy-preserving by design — the password never leaves your site; only the <strong>first 5 characters of its SHA-1 hash</strong> are sent (hundreds of passwords share that fragment, so the service cannot tell which one was checked). If the lookup service is unreachable the password is accepted and a warning is logged — an outage never blocks your users.', 'qevix-shield' ) ); ?>
					<label><input type="checkbox" name="pwd_block_breached" value="1" <?php checked( ! empty( $proValues['pwd_block_breached'] ) ); ?> /> <?php esc_html_e( 'Reject passwords found in known data breaches (Have I Been Pwned)', 'qevix-shield' ); ?></label>
					<p class="description"><?php esc_html_e( 'Checked at registration, profile update, and reset. Sends only a 5-character hash fragment to the lookup service — never the password.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="pwd_expiry_select"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Password Expiration', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Forces a fresh password once the current one reaches this age. Example: at <strong>90 days</strong>, a password set on 1 January must be replaced at the first login after 1 April. Users are sent to their profile page with a notice — they are never hard-locked out. The replacement can never be the same as the expiring password. <strong>Never</strong> disables expiry.', 'qevix-shield' ) ); ?>
					<select id="pwd_expiry_select" class="qevix-shield-min-select" data-custom-target="pwd_expiry_days">
						<option value="0" <?php selected( ! $expiryCustom && 0 === $expiryDays ); ?>><?php esc_html_e( 'Never', 'qevix-shield' ); ?></option>
						<option value="30" <?php selected( ! $expiryCustom && 30 === $expiryDays ); ?>><?php esc_html_e( 'Every 30 days', 'qevix-shield' ); ?></option>
						<option value="60" <?php selected( ! $expiryCustom && 60 === $expiryDays ); ?>><?php esc_html_e( 'Every 60 days', 'qevix-shield' ); ?></option>
						<option value="90" <?php selected( ! $expiryCustom && 90 === $expiryDays ); ?>><?php esc_html_e( 'Every 90 days', 'qevix-shield' ); ?></option>
						<option value="custom" <?php selected( $expiryCustom ); ?>><?php esc_html_e( 'Custom…', 'qevix-shield' ); ?></option>
					</select>
					<label class="qevix-shield-gap-left">
						<?php esc_html_e( 'Days:', 'qevix-shield' ); ?>
						<input type="number" class="qevix-shield-num-input" min="0" id="pwd_expiry_days" name="pwd_expiry_days" value="<?php echo esc_attr( $expiryDays ); ?>" />
					</label>
					<p class="description"><?php esc_html_e( 'Users are prompted to reset at next login once their password reaches this age (0 = never).', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="pwd_expiry_warn_days"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Expiry Warning', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Heads-up before expiry so users can change the password at a convenient moment instead of being surprised. Example: expiration 90 days + warning 7 shows a banner from day 83 onward.', 'qevix-shield' ) ); ?>
					<input type="number" class="qevix-shield-num-input" min="0" id="pwd_expiry_warn_days" name="pwd_expiry_warn_days" value="<?php echo esc_attr( $proValues['pwd_expiry_warn_days'] ); ?>" />
					<?php esc_html_e( 'days before expiry', 'qevix-shield' ); ?>
					<p class="description"><?php esc_html_e( 'Show a warning banner this many days before a password expires.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="pwd_history_select"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Password History', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Stops users from cycling back to an old password. Example: with <strong>last 5</strong>, a user changing their password cannot reuse any of their previous five. Only secure hashes are kept, never the passwords themselves. Even with history <strong>Off</strong>, reusing the current password is always rejected.', 'qevix-shield' ) ); ?>
					<select id="pwd_history_select" class="qevix-shield-min-select" data-custom-target="pwd_history_count">
						<option value="0" <?php selected( ! $historyCustom && 0 === $historyN ); ?>><?php esc_html_e( 'Off', 'qevix-shield' ); ?></option>
						<option value="3" <?php selected( ! $historyCustom && 3 === $historyN ); ?>><?php esc_html_e( 'Prevent reuse of last 3', 'qevix-shield' ); ?></option>
						<option value="5" <?php selected( ! $historyCustom && 5 === $historyN ); ?>><?php esc_html_e( 'Prevent reuse of last 5', 'qevix-shield' ); ?></option>
						<option value="10" <?php selected( ! $historyCustom && 10 === $historyN ); ?>><?php esc_html_e( 'Prevent reuse of last 10', 'qevix-shield' ); ?></option>
						<option value="custom" <?php selected( $historyCustom ); ?>><?php esc_html_e( 'Custom…', 'qevix-shield' ); ?></option>
					</select>
					<label class="qevix-shield-gap-left">
						<?php esc_html_e( 'Count:', 'qevix-shield' ); ?>
						<input type="number" class="qevix-shield-num-input" min="0" max="24" id="pwd_history_count" name="pwd_history_count" value="<?php echo esc_attr( $historyN ); ?>" />
					</label>
					<p class="description"><?php esc_html_e( 'Previous password hashes are stored (never plaintext); reuse is rejected.', 'qevix-shield' ); ?></p>
				</td>
			</tr>
		</table>

		<h3><?php esc_html_e( 'Force Password Reset', 'qevix-shield' ); ?></h3>
		<p class="description"><?php esc_html_e( 'Make the selected users set a new password at their next login — for example after a breach scare. This works on its own: it applies even when "Enforce password rules" above is off, and the new password must differ from the current one.', 'qevix-shield' ); ?></p>
		<table class="form-table">
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Scope', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Who the forced reset applies to. <strong>All users</strong>: everyone, including you. <strong>Selected roles</strong>: e.g. tick Subscriber + Author after a suspected leak of low-privilege accounts. <strong>Selected users</strong>: specific user IDs, comma-separated (find the ID in the Users list URL, e.g. <code>user_id=12</code>).', 'qevix-shield' ) ); ?>
					<label><input type="radio" name="force_scope" value="all" checked /> <?php esc_html_e( 'All users', 'qevix-shield' ); ?></label><br />
					<label><input type="radio" name="force_scope" value="roles" /> <?php esc_html_e( 'Selected roles', 'qevix-shield' ); ?></label>
					<span class="qevix-shield-choice-indent">
						<?php foreach ( wp_roles()->get_names() as $roleKey => $roleName ) : ?>
							<label><input type="checkbox" name="force_roles[]" value="<?php echo esc_attr( $roleKey ); ?>" /> <?php echo esc_html( translate_user_role( $roleName ) ); ?></label>
						<?php endforeach; ?>
					</span>
					<br />
					<label><input type="radio" name="force_scope" value="users" /> <?php esc_html_e( 'Selected users (IDs)', 'qevix-shield' ); ?></label>
					<input type="text" name="force_users" class="regular-text qevix-shield-gap-left" placeholder="12, 34, 56" />
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Require Reset at Next Login', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'The trigger for the scope above: check it and press Save Changes to flag those users once — each is sent to their profile page to set a new password at their next login (active sessions are not cut off). Use after a breach scare or when offboarding shared credentials.', 'qevix-shield' ) ); ?>
					<label><input type="checkbox" name="force_apply" value="1" /> <?php esc_html_e( 'Apply this on Save — require the scope above to reset their password at next login', 'qevix-shield' ); ?></label>
					<p class="description"><?php esc_html_e( 'A one-time action, not a saved setting — this box clears itself after each save.', 'qevix-shield' ); ?></p>
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
	QevixShield_Menu::render_pro_upsell(
		__( 'Advanced Password Security', 'qevix-shield' ),
		__( 'Qevix Shield Pro hardens passwords beyond the free length and character rules:', 'qevix-shield' ),
		array(
			__( 'Reject the 10,000 most-common, already-leaked passwords', 'qevix-shield' ),
			__( 'Expire passwords on a schedule, with a warning banner before the deadline', 'qevix-shield' ),
			__( 'Prevent reuse of previous passwords (configurable history)', 'qevix-shield' ),
			__( 'Force a password reset for everyone, selected roles, or specific users', 'qevix-shield' ),
		)
	);
	?>
<?php endif; ?>
