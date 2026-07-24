<?php
/**
 * Fired when the plugin is deleted from wp-admin. Removes the audit log
 * table and settings option unless "retain data on uninstall" was checked.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Server rules are behavior, not data: always strip the managed .htaccess
// blocks, regardless of the retain-data flag. (Deactivation already removes
// them, but uninstall can run after a manual re-add or a failed deactivate.)
require_once __DIR__ . '/includes/security/class-qevix-shield-file-security.php';
QevixShield_File_Security::remove_server_rules();

$settings = get_option( 'qevix_shield_settings', array() );
$retain   = ! empty( $settings['retain_data_on_uninstall'] );

if ( $retain ) {
	return;
}

global $wpdb;
$table = $wpdb->prefix . 'qevix_shield_logs';
$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name only, no user input.

delete_option( 'qevix_shield_settings' );
delete_option( 'qevix_shield_malware_results' );
delete_option( 'qevix_shield_alert_queue' );

// Short-lived per-user transients (2FA enrolment secret, recovery-code display,
// reCAPTCHA save notices) are dynamically named, so purge the families by
// prefix — value and timeout rows — rather than leaving any unexpired ones.
$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- fixed literal prefixes, no user input.
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\\_transient\\_qevix\\_shield\\_2fa\\_%'
	    OR option_name LIKE '\\_transient\\_timeout\\_qevix\\_shield\\_2fa\\_%'
	    OR option_name LIKE '\\_transient\\_qevix\\_shield\\_recaptcha\\_notice\\_%'
	    OR option_name LIKE '\\_transient\\_timeout\\_qevix\\_shield\\_recaptcha\\_notice\\_%'"
);

// Per-user two-factor data (free-owned since 2026-07-16). Pro's own uninstall
// clears its trusted-device / emailed-code meta.
foreach ( array( 'qevix_shield_2fa_secret', 'qevix_shield_2fa_enabled', 'qevix_shield_2fa_recovery', 'qevix_shield_2fa_login_nonce' ) as $meta_key ) {
	delete_metadata( 'user', 0, $meta_key, '', true ); // delete_all = true → every user.
}

$timestamp = wp_next_scheduled( 'qevix_shield_daily_log_cleanup' );
if ( $timestamp ) {
	wp_unschedule_event( $timestamp, 'qevix_shield_daily_log_cleanup' );
}
wp_clear_scheduled_hook( 'qevix_shield_send_alert' );
