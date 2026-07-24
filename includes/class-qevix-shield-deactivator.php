<?php
/**
 * Fired on plugin deactivation: clears the scheduled cron event and removes
 * the managed .htaccess rules (a deactivated plugin must not keep enforcing
 * server behavior). Settings and log data are left in place (see
 * uninstall.php for removal).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Deactivator {

	public static function deactivate() {
		$timestamp = wp_next_scheduled( 'qevix_shield_daily_log_cleanup' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'qevix_shield_daily_log_cleanup' );
		}

		// Pending batched alert send, if a collection window was open. The
		// queued events stay in their option: after reactivation they ride
		// along with the next batch that flushes; uninstall deletes them.
		wp_clear_scheduled_hook( 'qevix_shield_send_alert' );

		QevixShield_File_Security::remove_server_rules();
	}
}
