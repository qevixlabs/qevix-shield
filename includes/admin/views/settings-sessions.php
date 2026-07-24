<?php
/**
 * Sessions settings section (no page chrome — shared by the standalone submenu
 * page and the Settings > Sessions tab). Expects $sessions (own sessions, from
 * QevixShield_Sessions::get_user_sessions) and $is_pro.
 *
 * Free: the current user's own active sessions. Admin-wide session
 * management is injected by the pro plugin through the
 * qevix_shield_sessions_pro_fields action; free shows a locked preview instead.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<h3><?php esc_html_e( 'Sessions', 'qevix-shield' ); ?></h3>
<p class="description"><?php esc_html_e( 'See every device logged into your account and end the sessions you don\'t recognize.', 'qevix-shield' ); ?></p>

<?php if ( isset( $_GET['logged_out_others'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized. ?>
	<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Signed out of all your other sessions. Only this browser is still logged in.', 'qevix-shield' ); ?></p></div>
<?php endif; ?>

<details class="qevix-shield-report" open>
	<summary>
		<?php esc_html_e( 'Your Active Sessions', 'qevix-shield' ); ?>
		<span class="qevix-shield-report-count">
			<?php
			printf(
				/* translators: %d: number of active sessions */
				esc_html( _n( '%d session', '%d sessions', count( $sessions ), 'qevix-shield' ) ),
				(int) count( $sessions )
			);
			?>
		</span>
	</summary>
	<div class="qevix-shield-report-body">
<p class="description"><?php esc_html_e( 'Each row is one active login on your account — WordPress creates a separate session every time you sign in, so the same browser used over several days appears more than once. Expired logins are hidden automatically.', 'qevix-shield' ); ?></p>

<table class="widefat striped">
	<thead>
		<tr>
			<th><?php esc_html_e( 'Browser', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'IP', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Login Time', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Last Activity', 'qevix-shield' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php if ( empty( $sessions ) ) : ?>
			<tr><td colspan="4"><?php esc_html_e( 'No active sessions found.', 'qevix-shield' ); ?></td></tr>
		<?php else : ?>
			<?php foreach ( $sessions as $s ) : ?>
				<tr>
					<td>
						<?php echo esc_html( '' !== $s['browser'] ? $s['browser'] : __( 'Unknown', 'qevix-shield' ) ); ?>
						<?php if ( $s['is_current'] ) : ?>
							<span class="qevix-shield-session-current"><?php esc_html_e( '(this session)', 'qevix-shield' ); ?></span>
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( $s['ip'] ); ?></td>
					<td><?php echo esc_html( QevixShield_Sessions::format_time( $s['login'] ) ); ?></td>
					<td><?php echo esc_html( QevixShield_Sessions::format_time( $s['last_active'] ) ); ?></td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
	</tbody>
</table>

<?php
// Offer "log out everywhere else" only when there's more than one live
// session — otherwise there's nothing else to end.
$otherCount = 0;
foreach ( $sessions as $s ) {
	if ( empty( $s['is_current'] ) ) {
		$otherCount++;
	}
}
?>
<?php if ( $otherCount > 0 ) : ?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="qevix-shield-action-row" onsubmit="return confirm('<?php echo esc_js( __( 'Sign out of all your other sessions? This browser stays logged in.', 'qevix-shield' ) ); ?>');">
		<?php wp_nonce_field( 'qevix_shield_logout_others' ); ?>
		<input type="hidden" name="action" value="qevix_shield_logout_others" />
		<?php submit_button( __( 'Log out other sessions', 'qevix-shield' ), 'secondary', 'submit', false ); ?>
		<span class="description">
			<?php
			printf(
				/* translators: %d: number of other sessions that will be ended */
				esc_html( _n( 'Ends %d other session, keeps this browser.', 'Ends %d other sessions, keeps this browser.', $otherCount, 'qevix-shield' ) ),
				(int) $otherCount
			);
			?>
		</span>
	</form>
<?php endif; ?>
	</div>
</details>

<?php if ( ! $is_pro ) : ?>
	<?php
	// The reference look for every unlicensed pro section (see
	// QevixShield_Menu::render_pro_upsell) — this card was the original.
	QevixShield_Menu::render_pro_upsell(
		__( 'Admin Session Management', 'qevix-shield' ),
		__( 'Qevix Shield Pro lets administrators see and control every user\'s sessions:', 'qevix-shield' ),
		array(
			__( 'View active sessions across all users', 'qevix-shield' ),
			__( 'Revoke any individual session', 'qevix-shield' ),
			__( 'Log a user out everywhere — or force a global logout', 'qevix-shield' ),
			__( 'Auto-expire sessions after a configurable idle time', 'qevix-shield' ),
		)
	);
	?>
<?php endif; ?>

<?php
/**
 * Injection seam for the pro plugin's admin session-management UI. Pro's
 * callback self-gates on manage_options + QevixShield_Pro_License::is_valid()
 * and renders nothing otherwise (the locked preview above shows instead).
 */
do_action( 'qevix_shield_sessions_pro_fields', $is_pro );
