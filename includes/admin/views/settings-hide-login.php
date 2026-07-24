<?php
/**
 * Hide Admin Panel settings section (form only). Expects $settings.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="hide-login" />

	<?php
	$hideLoginOn   = (bool) $settings->get( 'hide_login_enabled', false );
	$loginSlugRaw  = trim( (string) $settings->get( 'login_slug', 'login' ), " \t\n\r\0\x0B/" );
	$redirectMode  = $settings->get( 'redirect_mode', '404' );
	$redirectUrl   = (string) $settings->get( 'redirect_custom_url', '' );
	?>
	<?php if ( isset( $_GET['qevix_shield_url_fallback'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only notice set by our own save redirect. ?>
		<div class="notice notice-warning is-dismissible"><p><?php esc_html_e( 'Custom URL mode needs a destination URL, and none was entered — blocked requests show a 404 Not Found instead. To use a custom redirect, pick "Custom URL" again and enter the full address.', 'qevix-shield' ); ?></p></div>
	<?php endif; ?>

	<h3><?php esc_html_e( 'Hide Admin Panel', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Move the login page to a secret address and block the well-known entry points (wp-login.php, wp-admin) for logged-out visitors.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Hide Login URL', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Master switch for this whole tab. While OFF, the site logs in at the normal <code>wp-login.php</code> and nothing below applies. Turning it ON moves login to the slug below and blocks the well-known URLs — <strong>bookmark the new address first</strong>. If you ever do get locked out, add <code>define( \'QEVIX_SHIELD_SAFE_MODE\', true );</code> to wp-config.php to suspend every protection without losing your settings.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="hide_login_enabled" value="1" <?php checked( $settings->get( 'hide_login_enabled', false ) ); ?> /> <?php esc_html_e( 'Hide the login page behind the custom slug below', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default — activating Qevix Shield never moves your login URL until you enable this.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="login_slug"><?php esc_html_e( 'Custom Login Slug', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Moves your login page to a secret address. Example: entering <code>my-portal</code> makes the login page <code>yoursite.com/my-portal</code> and blocks the well-known <code>wp-login.php</code>. Bookmark the new address BEFORE logging out — the old URL will no longer work. Registration and lost-password links move with it automatically.', 'qevix-shield' ) ); ?>
				<code><?php echo esc_html( home_url( '/' ) ); ?></code>
				<input type="text" name="login_slug" id="login_slug" value="<?php echo esc_attr( $settings->get( 'login_slug', 'login' ) ); ?>" class="regular-text" />
				<p class="description"><?php esc_html_e( 'Direct requests to wp-login.php, wp-register.php, wp-signup.php, and (while logged out) wp-admin will be blocked/redirected per the mode below.', 'qevix-shield' ); ?></p>
				<?php
				if ( $hideLoginOn && '' === $loginSlugRaw ) {
					QevixShield_Menu::dependency_notice( __( 'Hide Login is <strong>on</strong> but the slug is empty, so it falls back to <code>/login</code> — a URL attackers already guess. Enter a unique slug to actually hide the login page.', 'qevix-shield' ) );
				} elseif ( $hideLoginOn && 'login' === $loginSlugRaw ) {
					QevixShield_Menu::dependency_notice( __( 'Your login slug is <code>login</code>, one of the first URLs attackers try. Choose something unique so hiding the login page is effective.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Redirect Blocked Requests To', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'What a visitor sees when they hit the old, hidden login URLs. <strong>404 Not Found</strong> (recommended) pretends the page does not exist. <strong>Homepage</strong> quietly sends them to your front page. <strong>Custom URL</strong> sends them anywhere you choose — e.g. a decoy or info page.', 'qevix-shield' ) ); ?>
				<?php $mode = $settings->get( 'redirect_mode', '404' ); ?>
				<label><input type="radio" name="redirect_mode" value="404" <?php checked( $mode, '404' ); ?> /> <?php esc_html_e( '404 Not Found', 'qevix-shield' ); ?></label><br />
				<label><input type="radio" name="redirect_mode" value="home" <?php checked( $mode, 'home' ); ?> /> <?php esc_html_e( 'Homepage', 'qevix-shield' ); ?></label><br />
				<label><input type="radio" name="redirect_mode" value="custom" <?php checked( $mode, 'custom' ); ?> /> <?php esc_html_e( 'Custom URL', 'qevix-shield' ); ?></label>
				<input type="url" name="redirect_custom_url" id="qevix-shield-redirect-custom-url" value="<?php echo esc_attr( $settings->get( 'redirect_custom_url', '' ) ); ?>" class="regular-text" placeholder="https://example.com" <?php if ( 'custom' !== $mode ) : ?>hidden<?php endif; ?> />
			</td>
		</tr>
	</table>

	<?php submit_button( __( 'Save Changes', 'qevix-shield' ) ); ?>
</form>
