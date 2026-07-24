<?php
/**
 * Second-factor login challenge (rendered inside the wp-login.php lifecycle).
 * Expects: $user, $nonce, $redirectTo, $error, $emailSent, $emailFallback,
 * $trustedDevices.
 *
 * The "Trust this device" checkbox ($trustedDevices) and "Email me a code"
 * button ($emailFallback) are pro-only extras — they render only when the pro
 * plugin has enabled them through the qevix_shield_2fa_trusted_devices /
 * qevix_shield_2fa_email_fallback filters.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<?php
// Match core wp-login.php: the error sits between the logo and the form
// (not inside it), with the standard notice styling.
if ( ! empty( $error ) ) :
	?>
	<div id="login_error" class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
	<?php
endif;
?>
<?php
if ( ! empty( $emailSent ) ) :
	?>
	<p class="message"><?php esc_html_e( 'We emailed you a one-time code. Enter it below.', 'qevix-shield' ); ?></p>
	<?php
endif;
?>
<form name="qevix_shield_2fa_form" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=qevix_shield_2fa', 'login_post' ) ); ?>" method="post">
	<p>
		<label for="qevix_shield_2fa_code"><?php esc_html_e( 'Authentication Code', 'qevix-shield' ); ?></label>
		<input type="text" name="qevix_shield_2fa_code" id="qevix_shield_2fa_code" class="input" value="" size="20"
			inputmode="numeric" autocomplete="one-time-code" autofocus="autofocus" />
	</p>
	<p class="description"><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or a recovery code.', 'qevix-shield' ); ?></p>

	<?php if ( ! empty( $trustedDevices ) ) : ?>
		<p style="margin:12px 0;">
			<label><input type="checkbox" name="qevix_shield_2fa_trust" value="1" />
				<?php
				printf(
					/* translators: %d: number of days this browser will skip the 2FA code */
					esc_html( _n( 'Trust this device (skip the code here for %d day)', 'Trust this device (skip the code here for %d days)', (int) ( $trustedDays ?? 30 ), 'qevix-shield' ) ),
					(int) ( $trustedDays ?? 30 )
				);
				?>
			</label>
		</p>
	<?php endif; ?>

	<input type="hidden" name="qevix_shield_2fa_user" value="<?php echo esc_attr( $user->ID ); ?>" />
	<input type="hidden" name="qevix_shield_2fa_nonce" value="<?php echo esc_attr( $nonce ); ?>" />
	<input type="hidden" name="qevix_shield_2fa_method" value="totp" />
	<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirectTo ); ?>" />
	<?php if ( ! empty( $_REQUEST['rememberme'] ) ) : ?>
		<input type="hidden" name="rememberme" value="forever" />
	<?php endif; ?>

	<p class="submit">
		<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'qevix-shield' ); ?>" />
	</p>

	<?php if ( ! empty( $emailFallback ) ) : ?>
		<p style="text-align:center;margin:20px 0 4px;">
			<button type="submit" name="qevix_shield_2fa_method" value="email_send" class="button-link" style="cursor:pointer;background:none;border:none;color:#2271b1;text-decoration:underline;">
				<?php esc_html_e( 'Lost your device? Email me a code instead', 'qevix-shield' ); ?>
			</button>
		</p>
	<?php endif; ?>
</form>
