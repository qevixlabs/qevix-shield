<?php
/**
 * Thin wrapper around the single `qevix_shield_settings` option, plus the
 * admin-post handler that saves the General / Hide Admin Panel tabs.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Settings {

	const OPTION_KEY = 'qevix_shield_settings';

	/**
	 * Gates the Qevix Shield admin screens and their save handlers. Administrators
	 * always get it via `manage_options`; other roles can be granted it from the
	 * General tab (`access_roles`). Granted virtually through `user_has_cap`
	 * (grant_access_cap), not add_cap(), so removing a role takes effect immediately.
	 */
	const CAP = 'qevix_shield_manage';

	/**
	 * Read-only counterpart of CAP: opens Dashboard + Malware Scanner results
	 * with no save/action rights. Granted the same way to `view_roles`; CAP
	 * holders get it implicitly. Save handlers only ever check CAP.
	 */
	const VIEW_CAP = 'qevix_shield_view';

	private $cache;

	public function get_all() {
		if ( null === $this->cache ) {
			$this->cache = wp_parse_args( get_option( self::OPTION_KEY, array() ), $this->defaults() );
		}
		return $this->cache;
	}

	public function get( $key, $default = null ) {
		$all = $this->get_all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	public function update( array $values ) {
		$merged = array_merge( $this->get_all(), $values );
		update_option( self::OPTION_KEY, $merged );
		$this->cache = $merged;
	}

	private function defaults() {
		// Neutral-on-activation policy: every setting that actively changes the
		// site's responses, blocks/hardens requests, enforces password rules, or
		// sends outbound notifications ships OFF/empty, so a fresh install does
		// nothing until the admin reads each option and enables it deliberately.
		// Only passive, plugin-internal settings that don't touch the site keep a
		// value (audit-log retention, request logging, uninstall data handling).
		return array(
			// Login hiding is opt-in: OFF by default so activating the plugin
			// never silently moves the login URL (support-lockout hazard).
			'hide_login_enabled'        => false,
			'login_slug'                => 'login',
			'redirect_mode'             => '404',
			'redirect_custom_url'       => '',
			// Master switch for the whole Login Protection tab: while OFF, nothing
			// on it enforces (honeypot + rate limiting), so the sub-settings can be
			// drafted and activated later with one checkbox.
			'login_protection_enabled'  => false,
			'honeypot_enabled'          => false,
			'ip_whitelist'              => '',
			// Brute-force rate limiting / temporary IP lockout: opt-in (has its
			// own enable toggle so it never throttles logins until switched on).
			'rate_limit_enabled'        => false,
			'rate_limit_fails'          => 5,
			'rate_limit_window_minutes' => 15,
			'lockout_duration_minutes'  => 15,
			// Password policy: one master switch gates the whole rule set, then
			// minimum length, character classes, disallow username/email. Neutral
			// by default — the master is OFF so none of the rules apply on a fresh
			// install; the individual values are sensible presets for when it's on.
			'pwd_policy_enabled'        => false, // master: all password rules below apply only when true.
			'pwd_min_length'            => 8,     // 0 = no minimum length check (the master switch is the real on/off).
			'pwd_require_upper'         => false,
			'pwd_require_lower'         => false,
			'pwd_require_number'        => false,
			'pwd_require_special'       => false,
			'pwd_disallow_user_info'    => false,
			// XML-RPC protection: one master switch, then the mode + request
			// logging. The master (OFF by default) is the on/off; the mode no
			// longer carries an "off" value — it only picks HOW to protect once on.
			'xmlrpc_enabled'            => false,
			'xmlrpc_mode'               => 'disabled', // disabled | pingbacks (applies only when xmlrpc_enabled).
			'xmlrpc_logging'            => true,        // passive: logs to our own table, doesn't alter the site.
			// File security: one master switch for the whole tab (sensitive files,
			// hardening, firewall). OFF by default — none of it enforces until on.
			'file_security_enabled'     => false,
			// File security: block sensitive files (.env, .git, composer.json, …).
			'block_sensitive_files'     => false,
			// File security: direct-access hardening.
			'fs_block_meta_files'       => false, // readme/changelog/license files (plugin enumeration).
			'fs_block_direct_php'       => false, // direct .php hits under plugins/themes/wp-includes.
			'fs_disable_php_exec'       => false, // no PHP execution in uploads/cache/upgrade/backups/logs.
			'fs_disable_dir_listing'    => false, // no directory browsing under wp-content/wp-includes.
			// Hardening: information disclosure.
			'hide_wp_version'           => false,
			'hide_rest_api'             => false, // breaks anonymous REST consumers; opt-in.
			'block_author_enum'         => false,
			'block_user_enum'           => false,
			'hide_server_headers'       => false,
			'hide_php_errors'           => false,
			// Firewall (request signatures + bad bots).
			'firewall_enabled'          => false,
			'firewall_block_bad_bots'   => false,
			'firewall_inspect_post'     => false, // legit content can look attack-ish; opt-in.
			// Extra protected files (File Security tab). Both available on every
			// tier — this plugin implements the matcher, so neither may be gated
			// on a licence. OFF/empty on activation like every other rule.
			'fs_block_backups'          => false, // *.sql, *.bak, *.wpress … (BACKUP_SUFFIXES).
			'fs_custom_blocklist'       => '',    // admin-defined names or *.suffix patterns.
			// Two-Factor Auth (Two-Factor Auth tab). Master OFF on activation
			// (neutral default). The enforced role set is selectable on every tier (Administrator is the
			// default, not a ceiling). Trusted-device days and the emailed-code
			// fallback are implemented by the pro plugin, so it owns those keys.
			'twofa_enabled'             => false,
			'twofa_enforced_roles'      => array( 'administrator' ),
			// XML-RPC password logins for accounts that HAVE enrolled in 2FA.
			// WordPress accepts plain username+password over XML-RPC with no
			// second factor, which would otherwise sidestep 2FA entirely.
			// 'allow' = WordPress default (neutral on activation), 'code' =
			// require the 2FA code appended to the password, 'block' = reject.
			// Application-password logins are always exempt (each app password
			// is its own revocable credential, unrelated to the account password).
			'twofa_xmlrpc_mode'         => 'allow',
			// reCAPTCHA (reCAPTCHA tab). Master OFF; keys empty — but every
			// capability the engine implements is fully available on the free
			// tier: v2 AND v3, the score threshold, all three wp-login forms,
			// and the email verification fallback. Nothing here is gated on a
			// licence (wp.org Guideline 5 — a feature whose code ships in this
			// plugin may not be locked behind one). Pro adds only what it
			// implements itself: WooCommerce form coverage and the bridge
			// actions for other plugins' forms.
			// The Secret Key is write-only (blank field = keep saved).
			'recaptcha_enabled'         => false,
			'recaptcha_site_key'        => '',
			'recaptcha_secret_key'      => '',
			'recaptcha_version'         => 'v2',  // 'v2' (checkbox) or 'v3' (invisible, score-based).
			'recaptcha_threshold'       => 0.5,   // v3 only: reject below this score (0.0–1.0).
			'recaptcha_email_fallback'  => false, // v3 only: email a one-time sign-in link when the score rejects a human.
			'recaptcha_forms'           => array( 'login' ),
			// Fingerprint of the site key + version + secret that last passed the
			// "Test keys" preflight (QevixShield_Recaptcha::fingerprint()). The
			// master switch cannot be turned on until this matches the values
			// being saved — a v2/v3 key mismatch fails entirely in the browser
			// (no token is ever minted), so it must be caught here rather than at
			// login time, where it would lock every user out.
			'recaptcha_verified'        => '',
			// Malware scanner scan scope: nothing pre-selected — the admin ticks
			// what a scan should cover.
			'scan_scopes'               => array(),
			// Email alerts for critical events: OFF by default; the admin opts in
			// on the Notifications tab. Recipients live in `admin_emails` below.
			'alerts_enabled'            => false,
			// How many days of audit log to keep; the daily cleanup deletes older
			// rows. Admin-configurable (General tab); default 7. Passive/internal
			// (our own log data, never touches the site) so it keeps a value. Fed
			// to the retention cutoff via the qevix_shield_log_retention_days filter.
			'log_retention_days'        => 7,
			'retain_data_on_uninstall'  => false,
			// Access control + admin contacts (General tab).
			'access_roles'              => array(), // extra roles allowed into the plugin (beyond administrators).
			'view_roles'                => array(), // roles with read-only access (Dashboard + scan results; no saves).
			'admin_emails'              => '',      // newline/comma EXTRA recipients (Notifications tab); the WP admin email is always included on top.
		);
	}

	/**
	 * Roles (beyond administrators) allowed to access the plugin, as configured
	 * on the General tab. Sanitized to role-key form.
	 *
	 * @return string[]
	 */
	public function get_access_roles() {
		$roles = $this->get( 'access_roles', array() );
		if ( ! is_array( $roles ) ) {
			return array();
		}
		return array_values( array_filter( array_map( 'sanitize_key', $roles ) ) );
	}

	/**
	 * Roles granted read-only access (VIEW_CAP) from the General tab.
	 *
	 * @return string[]
	 */
	public function get_view_roles() {
		$roles = $this->get( 'view_roles', array() );
		if ( ! is_array( $roles ) ) {
			return array();
		}
		return array_values( array_filter( array_map( 'sanitize_key', $roles ) ) );
	}

	/**
	 * Notification recipients: the WP admin email is always included (fixed
	 * baseline, editable only under Settings → General), plus whatever extra
	 * addresses are configured in `admin_emails`.
	 *
	 * @return string[] Non-empty list of valid email addresses.
	 */
	public function get_admin_emails() {
		$emails = array();

		$wpAdmin = (string) get_option( 'admin_email' );
		if ( '' !== $wpAdmin && is_email( $wpAdmin ) ) {
			$emails[] = $wpAdmin;
		}

		$raw   = (string) $this->get( 'admin_emails', '' );
		$parts = preg_split( '/[\r\n,]+/', $raw );
		foreach ( (array) $parts as $part ) {
			$part = trim( $part );
			if ( '' !== $part && is_email( $part ) ) {
				$emails[] = $part;
			}
		}

		if ( empty( $emails ) ) {
			$emails[] = $wpAdmin; // Fall back if the WP admin email is itself unset/invalid.
		}

		return array_values( array_unique( $emails ) );
	}

	/**
	 * Admin-configured log retention, in days. Clamped to a minimum of 1 so
	 * the daily cleanup can never be handed 0 or a negative number.
	 *
	 * @return int
	 */
	public function get_log_retention_days() {
		return max( 1, (int) $this->get( 'log_retention_days', 7 ) );
	}

	/**
	 * Supplies the admin-configured retention to QevixShield_Audit_Log's cleanup
	 * job via the `qevix_shield_log_retention_days` filter. Registered
	 * unconditionally so it also applies during the WP-cron run, not just
	 * wp-admin. Pro can still override on top at a later priority.
	 *
	 * @param int $days Incoming default (7).
	 * @return int
	 */
	public function filter_log_retention_days( $days ) {
		return $this->get_log_retention_days();
	}

	/**
	 * Hooked on `user_has_cap`: grants the Qevix Shield access capability to
	 * administrators and to any user whose role is in `access_roles`. Kept
	 * cheap since this runs on every capability check.
	 *
	 * @param array    $allCaps User's capability map.
	 * @param string[] $caps    Required primitive caps (unused).
	 * @param array    $args    [ requested_cap, user_id, ...object ] (unused).
	 * @param WP_User  $user    The user being checked.
	 * @return array
	 */
	public function grant_access_cap( $allCaps, $caps, $args, $user ) {
		if ( ! empty( $allCaps['manage_options'] ) ) {
			$allCaps[ self::CAP ]      = true;
			$allCaps[ self::VIEW_CAP ] = true;
			return $allCaps;
		}

		if ( ! $user instanceof WP_User ) {
			return $allCaps;
		}
		$userRoles = (array) $user->roles;

		$roles = $this->get_access_roles();
		if ( ! empty( $roles ) && array_intersect( $roles, $userRoles ) ) {
			$allCaps[ self::CAP ]      = true;
			$allCaps[ self::VIEW_CAP ] = true; // Manage implies view.
			return $allCaps;
		}

		$viewRoles = $this->get_view_roles();
		if ( ! empty( $viewRoles ) && array_intersect( $viewRoles, $userRoles ) ) {
			$allCaps[ self::VIEW_CAP ] = true;
		}

		return $allCaps;
	}

	/** Settings-tab render callbacks (see QevixShield_Menu::register_settings_tabs). */
	public function render_general_section() {
		$settings = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-general.php';
	}

	public function render_hide_login_section() {
		$settings = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-hide-login.php';
	}

	public function render_login_protection_section() {
		$settings = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-login-protection.php';
	}

	public function render_password_security_section() {
		$settings = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-password-security.php';
	}

	public function render_xmlrpc_section() {
		$settings = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-xmlrpc.php';
	}

	public function render_notifications_section() {
		$settings = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-notifications.php';
	}

	/**
	 * Hooked on admin_post_qevix_shield_save_settings.
	 */
	public function handle_save() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'qevix-shield' ), 403 );
		}

		check_admin_referer( 'qevix_shield_save_settings' );

		$tab = isset( $_POST['qevix_shield_tab'] ) ? sanitize_key( wp_unslash( $_POST['qevix_shield_tab'] ) ) : 'general';

		// Extra query args for the redirect below, e.g. to explain a value the
		// save had to change (never change a choice silently).
		$extraArgs = array();

		if ( 'hide-login' === $tab ) {
			$mode      = isset( $_POST['redirect_mode'] ) && in_array( $_POST['redirect_mode'], array( '404', 'home', 'custom' ), true ) ? sanitize_key( wp_unslash( $_POST['redirect_mode'] ) ) : '404';
			$customUrl = isset( $_POST['redirect_custom_url'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_custom_url'] ) ) : '';

			// The URL only matters in 'custom' mode — never store it for the other
			// modes, and 'custom' without a usable URL falls back to '404' so the
			// two can't drift out of sync. The fallback is announced on the tab
			// (qevix_shield_url_fallback notice), not applied silently.
			if ( 'custom' !== $mode ) {
				$customUrl = '';
			} elseif ( '' === $customUrl ) {
				$mode                          = '404';
				$extraArgs['qevix_shield_url_fallback']  = 1;
			}

			$this->update(
				array(
					'hide_login_enabled'  => ! empty( $_POST['hide_login_enabled'] ),
					'login_slug'          => isset( $_POST['login_slug'] ) ? sanitize_title( wp_unslash( $_POST['login_slug'] ) ) : 'login',
					'redirect_mode'       => $mode,
					'redirect_custom_url' => $customUrl,
				)
			);
		} elseif ( 'login-protection' === $tab ) {
			$this->update(
				array(
					'login_protection_enabled'  => ! empty( $_POST['login_protection_enabled'] ),
					'honeypot_enabled'          => ! empty( $_POST['honeypot_enabled'] ),
					'ip_whitelist'              => isset( $_POST['ip_whitelist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ip_whitelist'] ) ) : '',
					'rate_limit_enabled'        => ! empty( $_POST['rate_limit_enabled'] ),
					'rate_limit_fails'          => isset( $_POST['rate_limit_fails'] ) ? max( 1, absint( $_POST['rate_limit_fails'] ) ) : 5,
					'rate_limit_window_minutes' => isset( $_POST['rate_limit_window_minutes'] ) ? max( 1, absint( $_POST['rate_limit_window_minutes'] ) ) : 15,
					'lockout_duration_minutes'  => isset( $_POST['lockout_duration_minutes'] ) ? max( 1, absint( $_POST['lockout_duration_minutes'] ) ) : 15,
				)
			);

			/**
			 * The Advanced Login Protection (pro) fields live in this same form
			 * with a single Save button. Free never persists those keys itself:
			 * pro's listener (self-gated on its license + manage_options) reads
			 * them from $_POST. Without a licensed pro plugin there is no
			 * listener and the keys are ignored — nonce + capability were
			 * already verified above.
			 */
			do_action( 'qevix_shield_login_protection_save_pro' );
		} elseif ( 'password-security' === $tab ) {
			$this->update(
				array(
					'pwd_policy_enabled'     => ! empty( $_POST['pwd_policy_enabled'] ),
					'pwd_min_length'         => isset( $_POST['pwd_min_length'] ) ? min( 256, absint( $_POST['pwd_min_length'] ) ) : 8, // 0 = no minimum length check.
					'pwd_require_upper'      => ! empty( $_POST['pwd_require_upper'] ),
					'pwd_require_lower'      => ! empty( $_POST['pwd_require_lower'] ),
					'pwd_require_number'     => ! empty( $_POST['pwd_require_number'] ),
					'pwd_require_special'    => ! empty( $_POST['pwd_require_special'] ),
					'pwd_disallow_user_info' => ! empty( $_POST['pwd_disallow_user_info'] ),
				)
			);

			// Advanced Password Security (pro) fields live in this same form with
			// a single Save button; pro's listener persists them (see the Login
			// Protection pattern in class-qevix-shield.php's comment).
			do_action( 'qevix_shield_password_security_save_pro' );

			// Force Password Reset is a one-shot action, not a saved setting: Scope
			// + the "Require Reset at Next Login" checkbox live in this same form.
			// Free never acts on it; pro's listener reads it from $_POST and does
			// nothing when the checkbox is unchecked/absent.
			do_action( 'qevix_shield_password_force_reset_pro' );
		} elseif ( 'xmlrpc' === $tab ) {
			$this->update(
				array(
					'xmlrpc_enabled' => ! empty( $_POST['xmlrpc_enabled'] ),
					'xmlrpc_mode'    => isset( $_POST['xmlrpc_mode'] ) && in_array( $_POST['xmlrpc_mode'], array( 'disabled', 'pingbacks' ), true ) ? sanitize_key( wp_unslash( $_POST['xmlrpc_mode'] ) ) : 'disabled',
					'xmlrpc_logging' => ! empty( $_POST['xmlrpc_logging'] ),
				)
			);

			// Granular XML-RPC (pro) fields share this form + Save button.
			do_action( 'qevix_shield_xmlrpc_save_pro' );
		} elseif ( 'file-security' === $tab ) {
			$this->update(
				array(
					'file_security_enabled'   => ! empty( $_POST['file_security_enabled'] ),
					'block_sensitive_files'   => ! empty( $_POST['block_sensitive_files'] ),
					'fs_block_meta_files'     => ! empty( $_POST['fs_block_meta_files'] ),
					'fs_block_backups'        => ! empty( $_POST['fs_block_backups'] ),
					'fs_custom_blocklist'     => isset( $_POST['fs_custom_blocklist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['fs_custom_blocklist'] ) ) : '',
					'fs_block_direct_php'     => ! empty( $_POST['fs_block_direct_php'] ),
					'fs_disable_php_exec'     => ! empty( $_POST['fs_disable_php_exec'] ),
					'fs_disable_dir_listing'  => ! empty( $_POST['fs_disable_dir_listing'] ),
					'hide_wp_version'         => ! empty( $_POST['hide_wp_version'] ),
					'hide_rest_api'           => ! empty( $_POST['hide_rest_api'] ),
					'block_author_enum'       => ! empty( $_POST['block_author_enum'] ),
					'block_user_enum'         => ! empty( $_POST['block_user_enum'] ),
					'hide_server_headers'     => ! empty( $_POST['hide_server_headers'] ),
					'hide_php_errors'         => ! empty( $_POST['hide_php_errors'] ),
					'firewall_enabled'        => ! empty( $_POST['firewall_enabled'] ),
					'firewall_block_bad_bots' => ! empty( $_POST['firewall_block_bad_bots'] ),
					'firewall_inspect_post'   => ! empty( $_POST['firewall_inspect_post'] ),
				)
			);
			/**
			 * The Advanced File Security (pro) fields live in this same form
			 * with a single Save button. Free never persists those keys; pro's
			 * listener (self-gated on its license + manage_options) reads them
			 * from $_POST. Fired BEFORE the server-rules re-sync below so newly
			 * saved pro patterns land in the regenerated .htaccess block.
			 */
			do_action( 'qevix_shield_file_security_save_pro' );

			// Re-sync the managed .htaccess rules to the new toggles
			// (QevixShield_File_Security::sync_server_rules; no-op off Apache).
			do_action( 'qevix_shield_sync_server_rules' );
		} elseif ( 'malware' === $tab ) {
			$scopes = isset( $_POST['scan_scopes'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['scan_scopes'] ) ) : array();
			$this->update( array( 'scan_scopes' => array_values( array_unique( $scopes ) ) ) );

			/**
			 * The Advanced Malware Protection (pro) fields live in this same
			 * form with a single Save button. Free never persists those keys
			 * itself: pro's listener (self-gated on its license + manage_options)
			 * reads them from $_POST. Without a licensed pro plugin there is no
			 * listener and the keys are ignored — nonce + capability were
			 * already verified above.
			 */
			do_action( 'qevix_shield_malware_save_pro' );
		} elseif ( 'notifications' === $tab ) {
			// Recipients live here (moved from the General tab): the WordPress
			// admin email is always a recipient (added by get_admin_emails);
			// `admin_emails` holds only the extra addresses configured here.
			$emailsRaw = isset( $_POST['admin_emails'] ) ? sanitize_textarea_field( wp_unslash( $_POST['admin_emails'] ) ) : '';
			$emails    = array();
			foreach ( preg_split( '/[\r\n,]+/', $emailsRaw ) as $candidate ) {
				$candidate = trim( $candidate );
				if ( '' !== $candidate ) {
					$clean = sanitize_email( $candidate );
					if ( '' !== $clean && is_email( $clean ) ) {
						$emails[] = $clean;
					}
				}
			}

			$this->update(
				array(
					'alerts_enabled' => ! empty( $_POST['alerts_enabled'] ),
					'admin_emails'   => implode( "\n", array_values( array_unique( $emails ) ) ),
				)
			);

			// Advanced Notifications (pro) fields live in this same form with
			// a single Save button; pro's listener persists them (see the
			// Login Protection pattern above).
			do_action( 'qevix_shield_notifications_save_pro' );
		} else {
			// General tab: access control + uninstall. (Recipients moved to the
			// Notifications tab.)
			$validRoles = array_keys( wp_roles()->get_names() );
			$roles      = isset( $_POST['access_roles'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['access_roles'] ) ) : array();
			$roles      = array_values( array_intersect( $validRoles, $roles ) );
			// Administrator access is implicit (via manage_options); never store it.
			$roles = array_values( array_diff( $roles, array( 'administrator' ) ) );

			$viewRoles = isset( $_POST['view_roles'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['view_roles'] ) ) : array();
			$viewRoles = array_values( array_intersect( $validRoles, $viewRoles ) );
			$viewRoles = array_values( array_diff( $viewRoles, array( 'administrator' ) ) );

			$this->update(
				array(
					'access_roles'             => $roles,
					'view_roles'               => $viewRoles,
					'log_retention_days'       => isset( $_POST['log_retention_days'] ) ? max( 1, absint( $_POST['log_retention_days'] ) ) : 7,
					'retain_data_on_uninstall' => ! empty( $_POST['retain_data_on_uninstall'] ),
				)
			);
		}

		$redirect = add_query_arg(
			array_merge(
				array(
					'page'    => 'qevix-shield-settings',
					'tab'     => $tab,
					'updated' => 'true',
				),
				$extraArgs
			),
			admin_url( 'admin.php' )
		);
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Returns the whitelist option as a normalized array of single IPs.
	 *
	 * Deliberately IP-only (the tier boundary): CIDR range entries are
	 * dropped here so they can't silently work on the free tier — whole-range
	 * whitelisting is the pro `whitelist_cidr` setting. Both consumers (the
	 * login-protection filter and the firewall's early direct read) share
	 * this parse, so they always agree.
	 */
	public function get_ip_whitelist() {
		$raw     = (string) $this->get( 'ip_whitelist', '' );
		$entries = preg_split( '/[\r\n,]+/', $raw );
		$ips     = array();
		foreach ( (array) $entries as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' !== $entry && filter_var( $entry, FILTER_VALIDATE_IP ) ) {
				$ips[] = $entry;
			}
		}
		return $ips;
	}
}
