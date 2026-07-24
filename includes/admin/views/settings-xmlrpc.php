<?php
/**
 * XML-RPC Protection settings section (form only — no page chrome; used by the
 * Settings > XML-RPC Protection tab). Expects $settings.
 *
 * Single-form pattern (same as Login Protection): ONE form, ONE Save button.
 * The free fields (mode + logging) are always editable. The pro "Granular
 * XML-RPC Control" fields sit in the SAME form: unlicensed shows the upsell
 * card (`QevixShield_Menu::render_pro_upsell`) instead of the fields — never an
 * inert copy of them; licensed non-admins get them read-only in a bordered
 * `<fieldset disabled>`; licensed admins edit them inline. Free ships the
 * display defaults via `qevix_shield_xmlrpc_pro_values`; the pro plugin overlays
 * saved values and persists them on `qevix_shield_xmlrpc_save_pro`.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$isPro       = (bool) apply_filters( 'qevix_shield_is_pro_active', false );
$xmlrpcOn    = (bool) $settings->get( 'xmlrpc_enabled', false );
// The mode no longer has an "off" value — the master switch above is on/off.
// Any legacy 'off'/'none' falls back to 'disabled' so a real mode is selected.
$mode        = (string) $settings->get( 'xmlrpc_mode', 'disabled' );
$mode        = in_array( $mode, array( 'disabled', 'pingbacks' ), true ) ? $mode : 'disabled';
$proEditable = $isPro && current_user_can( 'manage_options' );

$proValues = (array) apply_filters(
	'qevix_shield_xmlrpc_pro_values',
	array(
		'xmlrpc_pro_mode'        => 'off',
		'xmlrpc_allowed_methods' => '',
		'xmlrpc_trusted_ips'     => '',
	)
);
$proMode = (string) $proValues['xmlrpc_pro_mode'];
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="xmlrpc" />

	<h3><?php esc_html_e( 'XML-RPC Protection', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Control access to xmlrpc.php, a common target for brute-force and pingback abuse.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Enable XML-RPC Protection', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Master switch. While OFF, XML-RPC is left exactly as WordPress ships it and nothing below applies. Turn it ON to enforce the mode you pick below (and to log requests, if enabled).', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="xmlrpc_enabled" value="1" <?php checked( $xmlrpcOn ); ?> /> <?php esc_html_e( 'Protect XML-RPC (apply the mode and logging below)', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default — XML-RPC behaves as stock WordPress until you enable this.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Protection Mode', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'How to protect XML-RPC once enabled above. <code>xmlrpc.php</code> is WordPress\'s legacy remote interface — used by the old mobile apps, some Jetpack features, and remote publishing tools, but also a favourite brute-force and pingback-abuse target. If nothing you use connects that way, choose <strong>Disable all</strong>. <strong>Disable pingbacks only</strong> keeps remote publishing working while stopping the most-abused method.', 'qevix-shield' ) ); ?>
				<label><input type="radio" name="xmlrpc_mode" value="disabled" <?php checked( $mode, 'disabled' ); ?> /> <?php esc_html_e( 'Disable all XML-RPC methods', 'qevix-shield' ); ?></label><br />
				<label><input type="radio" name="xmlrpc_mode" value="pingbacks" <?php checked( $mode, 'pingbacks' ); ?> /> <?php esc_html_e( 'Disable pingbacks only', 'qevix-shield' ); ?></label>
				<?php
				if ( ! $xmlrpcOn ) {
					QevixShield_Menu::dependency_notice( __( 'XML-RPC Protection is <strong>off</strong> above, so this mode is not applied yet. Enable it to activate protection.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Request Logging', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Records every XML-RPC call — e.g. <code>xmlrpc:wp.getUsersBlogs (blocked)</code> — on the Audit Log screen. Useful for seeing whether anything legitimate still uses XML-RPC before you disable it, and for spotting brute-force attempts.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="xmlrpc_logging" value="1" <?php checked( $settings->get( 'xmlrpc_logging', true ) ); ?> /> <?php esc_html_e( 'Log all XML-RPC requests (allowed and blocked) to the audit log', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Each request is recorded with its method name and result on the Audit Log screen.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
	</table>

	<?php
	$proLock = $proEditable ? '' : '<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span> ';
	?>
	<?php if ( $isPro ) : ?>

	<?php if ( ! $proEditable ) : ?>
	<fieldset class="qevix-shield-pro-fieldset" disabled>
		<legend>
			<span class="dashicons dashicons-lock qevix-shield-lock-icon" aria-hidden="true"></span>
			<?php esc_html_e( 'Granular XML-RPC Control (Pro)', 'qevix-shield' ); ?>
		</legend>
		<p class="description"><?php esc_html_e( 'These settings can only be changed by an administrator.', 'qevix-shield' ); ?></p>
	<?php else : ?>
		<h3><?php esc_html_e( 'Granular XML-RPC Control', 'qevix-shield' ); ?></h3>
		<p class="description"><?php esc_html_e( 'Applies on top of the free mode above. A free "Disabled" setting always takes precedence.', 'qevix-shield' ); ?></p>
	<?php endif; ?>

		<table class="form-table">
			<tr>
				<th scope="row"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Granular Mode', 'qevix-shield' ); ?></th>
				<td><?php QevixShield_Menu::help_tip( __( 'Finer rules layered on top of the Protection Mode above (a free "Disabled" always wins). <strong>Authenticated only</strong>: blocks the methods usable without a login, like pingbacks. <strong>Allow only selected methods</strong>: everything is blocked except the list below. <strong>Allow only trusted IPs</strong>: only the listed addresses may talk to XML-RPC at all.', 'qevix-shield' ) ); ?>
					<label><input type="radio" name="xmlrpc_pro_mode" value="off" <?php checked( in_array( $proMode, array( 'off', 'none' ), true ) ); ?> /> <?php esc_html_e( 'Off — use the Protection Mode above only', 'qevix-shield' ); ?></label><br />
					<label><input type="radio" name="xmlrpc_pro_mode" value="authenticated" <?php checked( $proMode, 'authenticated' ); ?> /> <?php esc_html_e( 'Authenticated requests only (block anonymous methods like pingback/demo)', 'qevix-shield' ); ?></label><br />
					<label><input type="radio" name="xmlrpc_pro_mode" value="allowlist" <?php checked( $proMode, 'allowlist' ); ?> /> <?php esc_html_e( 'Allow only selected methods', 'qevix-shield' ); ?></label><br />
					<label><input type="radio" name="xmlrpc_pro_mode" value="trusted_ips" <?php checked( $proMode, 'trusted_ips' ); ?> /> <?php esc_html_e( 'Allow only trusted IPs', 'qevix-shield' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="xmlrpc_allowed_methods"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Allowed Methods', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'The only XML-RPC methods that stay callable in "Allow only selected methods" mode, one per line — e.g. <code>wp.getPosts</code> if a headless client only reads posts. Method names are what the connecting app calls; its documentation lists them.', 'qevix-shield' ) ); ?>
					<textarea id="xmlrpc_allowed_methods" name="xmlrpc_allowed_methods" rows="4" class="large-text" placeholder="wp.getPosts&#10;wp.getMediaLibrary"><?php echo esc_textarea( $proValues['xmlrpc_allowed_methods'] ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One method name per line. Used only in "Allow only selected methods" mode — every other method is blocked.', 'qevix-shield' ); ?></p>
					<?php
					if ( 'allowlist' === $proMode && '' === trim( (string) $proValues['xmlrpc_allowed_methods'] ) ) {
						QevixShield_Menu::dependency_notice( __( 'Mode is <strong>Allow only selected methods</strong> but the list is empty, so <strong>every</strong> XML-RPC method is blocked. Add the methods your app needs, or pick a different mode.', 'qevix-shield' ) );
					}
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="xmlrpc_trusted_ips"><?php echo $proLock; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup. ?><?php esc_html_e( 'Trusted IPs', 'qevix-shield' ); ?></label></th>
				<td><?php QevixShield_Menu::help_tip( __( 'In "Allow only trusted IPs" mode, only these addresses may use XML-RPC — e.g. the fixed IP of the service that posts to your site (<code>203.0.113.5</code>) or its network range (<code>198.51.100.0/24</code>). One entry per line.', 'qevix-shield' ) ); ?>
					<textarea id="xmlrpc_trusted_ips" name="xmlrpc_trusted_ips" rows="4" class="large-text" placeholder="203.0.113.5&#10;198.51.100.0/24"><?php echo esc_textarea( $proValues['xmlrpc_trusted_ips'] ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One IP or IPv4 CIDR range per line. Used only in "Allow only trusted IPs" mode — every other IP is blocked.', 'qevix-shield' ); ?></p>
					<?php
					if ( 'trusted_ips' === $proMode && '' === trim( (string) $proValues['xmlrpc_trusted_ips'] ) ) {
						QevixShield_Menu::dependency_notice( __( 'Mode is <strong>Allow only trusted IPs</strong> but no IPs are listed, so <strong>all</strong> XML-RPC requests are blocked (including yours). Add at least one trusted IP, or pick a different mode.', 'qevix-shield' ) );
					}
					?>
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
		__( 'Granular XML-RPC Control', 'qevix-shield' ),
		__( 'Qevix Shield Pro layers finer rules on top of the free protection mode above:', 'qevix-shield' ),
		array(
			__( 'Allow authenticated requests only — block anonymous methods like pingbacks', 'qevix-shield' ),
			__( 'Method allowlist: block every XML-RPC method except the ones you name', 'qevix-shield' ),
			__( 'Trusted IPs only: restrict all XML-RPC access to listed addresses or CIDR ranges', 'qevix-shield' ),
			__( 'A free "Disabled" setting always takes precedence — Pro only ever adds blocks', 'qevix-shield' ),
		)
	);
	?>
<?php endif; ?>
