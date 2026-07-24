<?php
/**
 * Fired on plugin activation: creates the audit log table and schedules the
 * retention-cleanup cron event. (Settings are NOT seeded here — defaults live
 * only in QevixShield_Settings::defaults() and are merged at read time.)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Activator {

	public static function activate() {
		self::create_logs_table();

		// No settings seeding here on purpose: QevixShield_Settings::get_all()
		// merges the single source-of-truth defaults() at read time, so a
		// second hardcoded copy of the defaults would only drift (it did).
		// The option row materializes on the first settings save.

		if ( ! wp_next_scheduled( 'qevix_shield_daily_log_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'qevix_shield_daily_log_cleanup' );
		}
	}

	private static function create_logs_table() {
		global $wpdb;

		$tableName      = $wpdb->prefix . QEVIX_SHIELD_TABLE_LOGS;
		$charsetCollate = $wpdb->get_charset_collate();

		// Every read is `WHERE <col> = X [AND timestamp >= Y] ORDER BY timestamp DESC`,
		// so each filter column is paired with timestamp in a composite index:
		// (action, timestamp) covers the dashboard's per-action counts, (user_id, timestamp)
		// covers the dashboard's per-user My Activity query. module/severity/status ride the plain timestamp index instead —
		// they're interactive, retention-bounded lookups, not worth a dedicated index each.
		$sql = "CREATE TABLE {$tableName} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			timestamp DATETIME NOT NULL,
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			username VARCHAR(60) NOT NULL DEFAULT '',
			ip VARCHAR(45) NOT NULL DEFAULT '',
			user_agent VARCHAR(255) NOT NULL DEFAULT '',
			browser VARCHAR(100) NOT NULL DEFAULT '',
			action VARCHAR(100) NOT NULL DEFAULT '',
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			module VARCHAR(50) NOT NULL DEFAULT '',
			status VARCHAR(20) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY timestamp (timestamp),
			KEY action_time (action, timestamp),
			KEY user_time (user_id, timestamp)
		) {$charsetCollate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

}
