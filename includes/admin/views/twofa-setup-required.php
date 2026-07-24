<?php
/**
 * Forced 2FA enrollment — a standalone full-page screen served on admin_init
 * BEFORE any admin chrome, so an enforced-role user who hasn't enrolled never
 * sees the admin menu (or any other wp-admin page) at all. This is a complete
 * HTML document; the caller exits right after including it.
 *
 * Expects: $user (WP_User), $pendingSecret, $otpauthUri, $enrollError (bool).
 *
 * On successful confirmation handle_enroll() redirects to the normal 2FA admin
 * page (the recovery codes show there); on a bad code it redirects back into
 * wp-admin with enroll_error=1, which enforce_enrollment() intercepts and
 * re-renders this screen with the error notice.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="robots" content="noindex, nofollow" />
	<title><?php echo esc_html( sprintf( /* translators: %s site name */ __( 'Two-Factor Authentication Required — %s', 'qevix-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ) ); ?></title>
	<?php
	// Standalone full-page render (exits before any admin chrome, so no
	// admin_enqueue_scripts pass ever runs): register + print styles and
	// scripts through the enqueue API so no raw <style>/<script> tags are
	// emitted and versioning/dependencies are handled by core.
	wp_register_style( 'qevix-shield-login-forms', QEVIX_SHIELD_PLUGIN_URL . 'assets/css/login-forms.css', array(), QEVIX_SHIELD_VERSION );
	wp_print_styles( 'qevix-shield-login-forms' );

	wp_register_script( 'qevix-shield-qrcode', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/qrcode.js', array(), QEVIX_SHIELD_VERSION, false );
	wp_register_script( 'qevix-shield-twofa-qr', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/twofa-qr.js', array( 'qevix-shield-qrcode' ), QEVIX_SHIELD_VERSION, false );
	wp_add_inline_script( 'qevix-shield-twofa-qr', 'window.QevixShield2FAQR = ' . wp_json_encode( array( 'otpauth' => $otpauthUri ) ) . ';', 'before' );
	wp_print_scripts( 'qevix-shield-twofa-qr' );
	?>
</head>
<body>
	<div class="qevix-shield-2fa-setup">
		<h1><?php esc_html_e( 'Two-Factor Authentication Required', 'qevix-shield' ); ?></h1>
		<p><?php echo esc_html( sprintf( /* translators: %s user login */ __( 'Signed in as %s', 'qevix-shield' ), $user->user_login ) ); ?></p>

		<div class="qevix-shield-notice">
			<?php esc_html_e( 'Your role requires two-factor authentication. Set it up below to continue — the rest of the dashboard stays unavailable until you do.', 'qevix-shield' ); ?>
		</div>

		<?php if ( ! empty( $enrollError ) ) : ?>
			<div class="qevix-shield-notice qevix-shield-error">
				<?php esc_html_e( 'That code did not match. Make sure your device clock is correct and try again.', 'qevix-shield' ); ?>
			</div>
		<?php endif; ?>

		<details class="qevix-shield-guide">
			<summary><?php esc_html_e( 'Need help? First time using two-factor authentication — start here', 'qevix-shield' ); ?></summary>
			<div class="qevix-shield-guide-body">
				<p><?php esc_html_e( 'Two-factor authentication (2FA) adds a second lock to your account: besides your password, logging in also asks for a 6-digit code that only YOUR phone can produce. You need a free "authenticator" app on your phone — install any one of these (links open in a new tab):', 'qevix-shield' ); ?></p>
				<ul class="qevix-shield-apps">
					<li><a href="https://apps.apple.com/app/google-authenticator/id388497605" target="_blank" rel="noopener"><?php esc_html_e( 'Google Authenticator — iPhone ↗', 'qevix-shield' ); ?></a></li>
					<li><a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank" rel="noopener"><?php esc_html_e( 'Google Authenticator — Android ↗', 'qevix-shield' ); ?></a></li>
					<li><a href="https://www.microsoft.com/en-us/security/mobile-authenticator-app" target="_blank" rel="noopener"><?php esc_html_e( 'Microsoft Authenticator ↗', 'qevix-shield' ); ?></a></li>
					<li><a href="https://authy.com/download/" target="_blank" rel="noopener"><?php esc_html_e( 'Authy (phone + desktop) ↗', 'qevix-shield' ); ?></a></li>
				</ul>
				<p><?php esc_html_e( 'Once installed: open the app, tap "+" / "Add account" / "Scan QR code", point the camera at the QR code below, then type the 6-digit code the app shows into the confirmation box. If the code is rejected, check that your phone\'s clock is set to automatic.', 'qevix-shield' ); ?></p>
			</div>
		</details>

		<ol>
			<li><?php esc_html_e( 'Scan this QR code with Google Authenticator, Authy, 1Password, Bitwarden, or FreeOTP.', 'qevix-shield' ); ?></li>
			<li><?php esc_html_e( 'Or enter the key manually.', 'qevix-shield' ); ?></li>
			<li><?php esc_html_e( 'Then type the 6-digit code the app shows to confirm.', 'qevix-shield' ); ?></li>
		</ol>

		<div id="qevix-shield-2fa-qr"></div>

		<p><?php esc_html_e( 'Manual entry key:', 'qevix-shield' ); ?> <code><?php echo esc_html( $pendingSecret ); ?></code></p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'qevix_shield_2fa_enroll' ); ?>
			<input type="hidden" name="action" value="qevix_shield_2fa_enroll" />
			<p>
				<label for="qevix_shield_2fa_code"><strong><?php esc_html_e( 'Verification code', 'qevix-shield' ); ?></strong></label><br />
				<input type="text" inputmode="numeric" pattern="[0-9]*" name="qevix_shield_2fa_code" id="qevix_shield_2fa_code" autocomplete="one-time-code" placeholder="123456" autofocus />
			</p>
			<p><button type="submit" class="qevix-shield-submit"><?php esc_html_e( 'Verify & Submit', 'qevix-shield' ); ?></button></p>
		</form>

		<p class="qevix-shield-footer">
			<a href="<?php echo esc_url( wp_logout_url() ); ?>"><?php esc_html_e( 'Log out', 'qevix-shield' ); ?></a>
		</p>
	</div>
</body>
</html>
