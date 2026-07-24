<?php
/**
 * General settings section (form only). Expects $settings.
 *
 * Holds plugin-wide config: which roles may access Qevix Shield (access control)
 * and the uninstall data policy. (Notification recipients moved to the
 * Notifications tab.)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$accessRoles = $settings->get_access_roles();
$viewRoles   = $settings->get_view_roles();
$allRoles    = wp_roles()->get_names();
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="general" />

	<h3><?php esc_html_e( 'Access Control', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Choose which roles may manage Qevix Shield, and which get a read-only monitoring view.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><label for="access_roles"><?php esc_html_e( 'Allowed Roles', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Lets non-administrator roles open the Qevix Shield screens without making them full administrators. Example: select <strong>Editor</strong> so your content team can review the security log. Leave empty to keep Qevix Shield admin-only. Pro settings (license, quarantine) always stay administrator-only.', 'qevix-shield' ) ); ?>
				<select name="access_roles[]" id="access_roles" class="qevix-shield-role-select" multiple size="6">
					<?php
					foreach ( $allRoles as $roleKey => $roleName ) :
						if ( 'administrator' === $roleKey ) {
							continue; // Administrators always have access; not selectable.
						}
						?>
						<option value="<?php echo esc_attr( $roleKey ); ?>" <?php selected( in_array( $roleKey, $accessRoles, true ) ); ?>>
							<?php echo esc_html( translate_user_role( $roleName ) ); ?>
						</option>
					<?php endforeach; ?>
				</select>
				<p class="description">
					<?php esc_html_e( 'Administrators can always access Qevix Shield. Select additional roles that should be able to view and change these settings (hold Ctrl/Cmd to select several). Grant with care — these screens include the security log and firewall controls.', 'qevix-shield' ); ?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="view_roles"><?php esc_html_e( 'Read-Only Roles', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Gives a role a monitoring view only: the <strong>Dashboard</strong> and the <strong>Malware Scanner</strong> results, with every save button, scan trigger, and settings screen hidden. Example: select <strong>Editor</strong> so they can keep an eye on security status without being able to change anything. Roles selected under Allowed Roles already include this.', 'qevix-shield' ) ); ?>
				<select name="view_roles[]" id="view_roles" class="qevix-shield-role-select" multiple size="6">
					<?php
					foreach ( $allRoles as $roleKey => $roleName ) :
						if ( 'administrator' === $roleKey ) {
							continue; // Administrators always have access; not selectable.
						}
						?>
						<option value="<?php echo esc_attr( $roleKey ); ?>" <?php selected( in_array( $roleKey, $viewRoles, true ) ); ?>>
							<?php echo esc_html( translate_user_role( $roleName ) ); ?>
						</option>
					<?php endforeach; ?>
				</select>
				<p class="description">
					<?php esc_html_e( 'These roles get the full Dashboard (site-wide activity and the security widgets) plus the last malware scan results, but cannot save settings or run scans. Every logged-in user can already open the Dashboard to see their own recent activity, and manage their own Sessions, regardless of this setting.', 'qevix-shield' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'Log Retention', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'How much audit-log history to keep before the daily cleanup removes older entries.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><label for="log_retention_days"><?php esc_html_e( 'Keep Audit Log For', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'How many days of activity to keep in the audit log. A daily cleanup deletes anything older, so a larger number keeps more history but a bigger log table. Example: <strong>30</strong> to keep a month. Minimum 1 day.', 'qevix-shield' ) ); ?>
				<input type="number" name="log_retention_days" id="log_retention_days" min="1" step="1" value="<?php echo esc_attr( $settings->get_log_retention_days() ); ?>" class="small-text" />
				<?php esc_html_e( 'days', 'qevix-shield' ); ?>
				<p class="description"><?php esc_html_e( 'Older log entries are removed automatically once per day. Increase this to retain more history.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'Uninstall', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'What happens to Qevix Shield\'s settings and security log when the plugin is deleted.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Keep Data on Uninstall', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Applies only when you DELETE the plugin from the Plugins screen (not on deactivate). Checked: settings and the security log survive, so reinstalling picks up where you left off. Unchecked: the log table and all options are removed for a clean uninstall.', 'qevix-shield' ) ); ?><label><input type="checkbox" name="retain_data_on_uninstall" value="1" <?php checked( $settings->get( 'retain_data_on_uninstall', false ) ); ?> /> <?php esc_html_e( 'Keep settings and logs if this plugin is deleted', 'qevix-shield' ); ?></label></td>
		</tr>
	</table>

	<?php submit_button( __( 'Save Changes', 'qevix-shield' ) ); ?>
</form>
