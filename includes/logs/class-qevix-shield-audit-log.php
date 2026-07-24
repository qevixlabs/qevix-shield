<?php
/**
 * Audit log: writer, retention cleanup, search/filter, CSV export.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Audit_Log {

	/**
	 * Writes one row and fires qevix_shield_after_log so other modules
	 * (alerts now; malware scanner / XML-RPC / notifications later) can
	 * react without this class knowing about them.
	 *
	 * @param array $entry {
	 *   @type string $action   e.g. 'login_failed', 'login_success', 'lockout', 'user_created'
	 *   @type string $severity 'info'|'warning'|'critical'
	 *   @type string $module   e.g. 'auth', 'admin', 'system'
	 *   @type string $status   e.g. 'blocked', 'success', 'failed'
	 *   @type int    $user_id  optional, defaults to current user or 0
	 *   @type string $username optional, defaults to current user's login
	 * }
	 */
	public static function log( array $entry ) {
		global $wpdb;

		$userId   = isset( $entry['user_id'] ) ? (int) $entry['user_id'] : get_current_user_id();
		$username = isset( $entry['username'] ) ? $entry['username'] : '';

		if ( '' === $username && $userId ) {
			$user = get_userdata( $userId );
			if ( $user ) {
				$username = $user->user_login;
			}
		}

		$ip        = QevixShield_Util::get_client_ip();
		$userAgent = QevixShield_Util::get_user_agent();

		$row = array(
			'timestamp'  => current_time( 'mysql' ),
			'user_id'    => $userId,
			'username'   => $username,
			'ip'         => $ip,
			'user_agent' => $userAgent,
			'browser'    => QevixShield_Util::get_browser_name( $userAgent ),
			'action'     => isset( $entry['action'] ) ? $entry['action'] : '',
			'severity'   => isset( $entry['severity'] ) ? $entry['severity'] : 'info',
			'module'     => isset( $entry['module'] ) ? $entry['module'] : '',
			'status'     => isset( $entry['status'] ) ? $entry['status'] : '',
		);

		$table = $wpdb->prefix . QEVIX_SHIELD_TABLE_LOGS;
		$wpdb->insert( $table, $row );
		$row['id'] = $wpdb->insert_id;

		do_action( 'qevix_shield_after_log', $row );

		return $row;
	}

	/**
	 * @param array $args search, action, severity, module, user_id, date_from, date_to, paged, per_page
	 */
	public function query( array $args = array() ) {
		global $wpdb;

		$table = $wpdb->prefix . QEVIX_SHIELD_TABLE_LOGS;
		list( $where, $params ) = $this->build_where( $args );

		$perPage = isset( $args['per_page'] ) ? max( 1, (int) $args['per_page'] ) : 20;
		$paged   = isset( $args['paged'] ) ? max( 1, (int) $args['paged'] ) : 1;
		$offset  = ( $paged - 1 ) * $perPage;

		$sql = "SELECT * FROM {$table} {$where} ORDER BY timestamp DESC LIMIT %d OFFSET %d";
		$params[] = $perPage;
		$params[] = $offset;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $sql is built only from the fixed prefixed table name and build_where()'s placeholder-only clauses; every value goes through $wpdb->prepare() here.
		return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
	}

	public function count( array $args = array() ) {
		global $wpdb;

		$table = $wpdb->prefix . QEVIX_SHIELD_TABLE_LOGS;
		list( $where, $params ) = $this->build_where( $args );

		$sql = "SELECT COUNT(*) FROM {$table} {$where}";
		if ( $params ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $sql is built only from the fixed prefixed table name and build_where()'s placeholder-only clauses; every value goes through $wpdb->prepare() here.
			return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- constant query text: fixed prefixed table name, empty WHERE, no values at all.
		return (int) $wpdb->get_var( $sql );
	}

	private function build_where( array $args ) {
		global $wpdb;

		$clauses = array();
		$params  = array();

		if ( ! empty( $args['search'] ) ) {
			$like               = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$clauses[]          = '(username LIKE %s OR ip LIKE %s OR action LIKE %s OR status LIKE %s)';
			array_push( $params, $like, $like, $like, $like );
		}

		// Each equality filter also accepts an array of values (IN) — the
		// dashboard digest asks for severity warning+critical in one query.
		foreach ( array( 'action', 'severity', 'module', 'status' ) as $field ) {
			if ( empty( $args[ $field ] ) ) {
				continue;
			}
			if ( is_array( $args[ $field ] ) ) {
				$values       = array_values( $args[ $field ] );
				$placeholders = implode( ', ', array_fill( 0, count( $values ), '%s' ) );
				$clauses[]    = "{$field} IN ({$placeholders})";
				$params       = array_merge( $params, $values );
			} else {
				$clauses[] = "{$field} = %s";
				$params[]  = $args[ $field ];
			}
		}

		if ( ! empty( $args['user_id'] ) ) {
			$clauses[] = 'user_id = %d';
			$params[]  = (int) $args['user_id'];
		}

		// One account's own activity (the dashboard's My Activity view): rows
		// written under the user's ID plus username-only rows — failed logins
		// are logged before
		// any user is authenticated, so they carry user_id 0 and only the
		// username ties them to the account.
		if ( ! empty( $args['account'] ) && is_array( $args['account'] ) ) {
			$clauses[] = '( user_id = %d OR username = %s )';
			$params[]  = isset( $args['account']['id'] ) ? (int) $args['account']['id'] : 0;
			$params[]  = isset( $args['account']['login'] ) ? (string) $args['account']['login'] : '';
		}

		// Used by the realtime poll to fetch only rows newer than what the
		// browser already has.
		if ( ! empty( $args['after_id'] ) ) {
			$clauses[] = 'id > %d';
			$params[]  = (int) $args['after_id'];
		}

		if ( ! empty( $args['date_from'] ) ) {
			$clauses[] = 'timestamp >= %s';
			$params[]  = $args['date_from'] . ' 00:00:00';
		}

		if ( ! empty( $args['date_to'] ) ) {
			$clauses[] = 'timestamp <= %s';
			$params[]  = $args['date_to'] . ' 23:59:59';
		}

		$where = $clauses ? ( 'WHERE ' . implode( ' AND ', $clauses ) ) : '';

		return array( $where, $params );
	}

	/**
	 * Deletes log rows older than the configured retention window. The window
	 * comes through the `qevix_shield_log_retention_days` filter: the free plugin
	 * hooks it with the admin's General-tab setting (default 7), and pro can
	 * override on top — this method stays agnostic of where the number is set.
	 */
	public function cleanup_old_logs() {
		global $wpdb;

		$retentionDays = (int) apply_filters( 'qevix_shield_log_retention_days', 7 );
		$table         = $wpdb->prefix . QEVIX_SHIELD_TABLE_LOGS;
		// Cutoff is computed in SITE-LOCAL time to match log()'s current_time('mysql')
		// stamps. A UTC base here (current_time('timestamp', true)) would offset the
		// window by the site's timezone on non-UTC installs — deleting slightly too
		// much or too little. current_time('timestamp') is the same local frame the
		// stats buckets above use.
		$cutoff        = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $retentionDays * DAY_IN_SECONDS );

		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE timestamp < %s", $cutoff ) );
	}

	/**
	 * Hooked on admin_post_qevix_shield_export_csv. Streams every row
	 * matching the current filter (not just the current page) as CSV.
	 */
	public function handle_csv_export() {
		if ( ! current_user_can( QevixShield_Settings::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_export_csv' );

		$args = array(
			'search'   => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
			'action'   => isset( $_GET['filter_action'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_action'] ) ) : '',
			'severity' => isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '',
			'module'   => isset( $_GET['module'] ) ? sanitize_key( wp_unslash( $_GET['module'] ) ) : '',
			'per_page' => PHP_INT_MAX,
			'paged'    => 1,
		);

		$rows = $this->query( $args );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=qevix-shield-logs-' . current_time( 'Y-m-d' ) . '.csv' );

		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- streaming CSV to php://output; WP_Filesystem has no stream equivalent.
		fputcsv( $out, array( 'ID', 'Timestamp', 'User ID', 'Username', 'IP', 'User Agent', 'Browser', 'Action', 'Severity', 'Module', 'Status' ) );

		foreach ( $rows as $row ) {
			fputcsv( $out, array( $row->id, $row->timestamp, $row->user_id, $row->username, $row->ip, $row->user_agent, $row->browser, $row->action, $row->severity, $row->module, $row->status ) );
		}

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- closes the php://output stream above, not a file.
		exit;
	}

	/**
	 * Hooked on wp_ajax_qevix_shield_poll_logs. Returns only the rows created
	 * since the id the browser last saw (after_id), honoring the same filters
	 * as the Logs screen, so the realtime table can prepend new entries every
	 * few seconds without a full reload.
	 */
	public function ajax_poll() {
		if ( ! current_user_can( QevixShield_Settings::CAP ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		check_ajax_referer( 'qevix_shield_poll_logs', 'nonce' );

		$args = array(
			'search'   => isset( $_POST['s'] ) ? sanitize_text_field( wp_unslash( $_POST['s'] ) ) : '',
			'action'   => isset( $_POST['filter_action'] ) ? sanitize_text_field( wp_unslash( $_POST['filter_action'] ) ) : '',
			'severity' => isset( $_POST['severity'] ) ? sanitize_key( wp_unslash( $_POST['severity'] ) ) : '',
			'module'   => isset( $_POST['module'] ) ? sanitize_key( wp_unslash( $_POST['module'] ) ) : '',
			'after_id' => isset( $_POST['after_id'] ) ? max( 0, (int) $_POST['after_id'] ) : 0,
			'per_page' => 50,
			'paged'    => 1,
		);

		$rows = $this->query( $args );

		$payload = array();
		foreach ( $rows as $row ) {
			$payload[] = array(
				'id'        => (int) $row->id,
				'timestamp' => (string) $row->timestamp,
				'username'  => (string) $row->username,
				'ip'        => (string) $row->ip,
				'browser'   => (string) $row->browser,
				'action'    => (string) $row->action,
				'module'    => (string) $row->module,
				'severity'  => (string) $row->severity,
				'status'    => (string) $row->status,
			);
		}

		wp_send_json_success( array( 'rows' => $payload ) );
	}

	/*
	 * WordPress core event listeners: each just normalizes the hook's args into one log() call.
	 */

	public function on_login_success( $userLogin, $user ) {
		self::log(
			array(
				'action'   => 'login_success',
				'severity' => 'info',
				'module'   => 'auth',
				'status'   => 'success',
				'user_id'  => $user->ID,
				'username' => $userLogin,
			)
		);
	}

	public function on_login_failed( $username ) {
		self::log(
			array(
				'action'   => 'login_failed',
				'severity' => 'warning',
				'module'   => 'auth',
				'status'   => 'failed',
				'username' => $username,
			)
		);
	}

	public function on_logout( $userId ) {
		self::log(
			array(
				'action'   => 'logout',
				'severity' => 'info',
				'module'   => 'auth',
				'status'   => 'success',
				'user_id'  => $userId,
			)
		);
	}

	public function on_password_reset( $user ) {
		self::log(
			array(
				'action'   => 'password_reset',
				'severity' => 'info',
				'module'   => 'auth',
				'status'   => 'success',
				'user_id'  => $user->ID,
				'username' => $user->user_login,
			)
		);
	}

	public function on_user_register( $userId ) {
		self::log(
			array(
				'action'   => 'user_created',
				'severity' => 'info',
				'module'   => 'admin',
				'status'   => 'success',
				'user_id'  => $userId,
			)
		);
	}

	public function on_user_deleted( $userId ) {
		self::log(
			array(
				'action'   => 'user_deleted',
				'severity' => 'warning',
				'module'   => 'admin',
				'status'   => 'success',
				'user_id'  => $userId,
			)
		);
	}

	public function on_user_role_changed( $userId, $role, $oldRoles ) {
		self::log(
			array(
				'action'   => 'user_role_changed',
				'severity' => 'warning',
				'module'   => 'admin',
				'status'   => 'success',
				'user_id'  => $userId,
			)
		);
	}

	/*
	 * Qevix Shield self-monitoring: an option flipping, the plugin being
	 * updated/activated/deactivated, or any other settings change — logged
	 * under the `qevix-shield` module so pro can route it via the "Qevix Shield"
	 * notification category. `action` carries the affected option key or
	 * plugin slug after a colon, e.g. `option_disabled:firewall_enabled`.
	 */

	/**
	 * Returns the Qevix Shield plugin slug ('qevix-shield' / 'qevix-shield-pro')
	 * for a plugin basename path, or '' if it isn't one of ours.
	 */
	private function qevix_shield_plugin_slug( $plugin ) {
		$slug = dirname( (string) $plugin );
		return in_array( $slug, array( 'qevix-shield', 'qevix-shield-pro' ), true ) ? $slug : '';
	}

	public function on_plugin_activated( $plugin, $networkWide = false ) {
		$slug = $this->qevix_shield_plugin_slug( $plugin );
		if ( '' === $slug ) {
			return;
		}
		self::log(
			array(
				'action'   => 'plugin_activated:' . $slug,
				'severity' => 'info',
				'module'   => 'qevix-shield',
				'status'   => 'success',
			)
		);
	}

	public function on_plugin_deactivated( $plugin, $networkWide = false ) {
		$slug = $this->qevix_shield_plugin_slug( $plugin );
		if ( '' === $slug ) {
			return;
		}
		// Disabling the security suite is notable, not routine — warning.
		self::log(
			array(
				'action'   => 'plugin_deactivated:' . $slug,
				'severity' => 'warning',
				'module'   => 'qevix-shield',
				'status'   => 'success',
			)
		);
	}

	/**
	 * Hooked on upgrader_process_complete, which fires for every upgrader run
	 * (plugins, themes, core, translations) — filter down to plugin updates
	 * that touch qevix-shield / qevix-shield-pro.
	 */
	public function on_plugin_updated( $upgrader, $hookExtra ) {
		if ( ! is_array( $hookExtra ) || empty( $hookExtra['type'] ) || 'plugin' !== $hookExtra['type'] ) {
			return;
		}
		if ( isset( $hookExtra['action'] ) && 'update' !== $hookExtra['action'] ) {
			return;
		}

		if ( ! empty( $hookExtra['plugins'] ) && is_array( $hookExtra['plugins'] ) ) {
			$plugins = $hookExtra['plugins'];
		} elseif ( ! empty( $hookExtra['plugin'] ) ) {
			$plugins = array( $hookExtra['plugin'] );
		} else {
			return;
		}

		foreach ( $plugins as $plugin ) {
			$slug = $this->qevix_shield_plugin_slug( $plugin );
			if ( '' === $slug ) {
				continue;
			}
			self::log(
				array(
					'action'   => 'plugin_updated:' . $slug,
					'severity' => 'info',
					'module'   => 'qevix-shield',
					'status'   => 'success',
				)
			);
		}
	}

	/**
	 * Hooked on update_option_qevix_shield_settings and
	 * update_option_qevix_shield_pro_settings (both fire only when the stored
	 * value actually changed). Diffs old vs new: each boolean toggle that
	 * flipped gets its own enabled/disabled event, and every other changed
	 * key rolls up into ONE grouped `settings_changed:<key1,key2,…>` event
	 * naming exactly what a single Save touched (the old opaque
	 * `settings_changed:<plugin-slug>` row said nothing useful). Only keys
	 * present on both sides count, so a key materializing on first save
	 * isn't mistaken for a change.
	 */
	public function on_settings_changed( $oldValue, $value, $option ) {
		$known = array( 'qevix_shield_settings', 'qevix_shield_pro_settings' );
		if ( ! in_array( $option, $known, true ) ) {
			return;
		}

		$old = is_array( $oldValue ) ? $oldValue : array();
		$new = is_array( $value ) ? $value : array();

		$changedKeys = array();

		foreach ( $new as $key => $now ) {
			if ( ! array_key_exists( $key, $old ) ) {
				continue; // Newly materialized key, not a user toggle/change.
			}
			$had = $old[ $key ];

			// Boolean toggle (options are stored as real bools): compare as
			// bool so a true/1 or false/'' representation shift alone is inert.
			if ( is_bool( $had ) || is_bool( $now ) ) {
				if ( (bool) $had !== (bool) $now ) {
					self::log(
						array(
							'action'   => ( $now ? 'option_enabled:' : 'option_disabled:' ) . $key,
							'severity' => $now ? 'info' : 'warning',
							'module'   => 'qevix-shield',
							'status'   => 'success',
						)
					);
				}
				continue;
			}

			if ( $had !== $now ) {
				$changedKeys[] = $key;
			}
		}

		if ( ! empty( $changedKeys ) ) {
			// The action column is VARCHAR(100); list as many keys as fit and
			// fold the rest into a "+N" suffix so the row never truncates
			// mid-key. 90 leaves room for the suffix.
			$list = '';
			$more = 0;
			foreach ( $changedKeys as $key ) {
				$candidate = ( '' === $list ) ? $key : $list . ',' . $key;
				if ( strlen( 'settings_changed:' . $candidate ) > 90 ) {
					$more++;
					continue;
				}
				$list = $candidate;
			}
			if ( $more > 0 ) {
				$list .= '+' . $more;
			}
			self::log(
				array(
					'action'   => 'settings_changed:' . $list,
					'severity' => 'info',
					'module'   => 'qevix-shield',
					'status'   => 'success',
				)
			);
		}
	}
}
