<?php
/**
 * Dashboard widgets: the free set, plus six analytics cards computed from
 * this plugin's own data (shown on every tier; Pro may enrich two of them).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Dashboard {

	/** @var QevixShield_Audit_Log */
	private $audit_log;

	public function __construct( QevixShield_Audit_Log $audit_log ) {
		$this->audit_log = $audit_log;
	}

	public function render() {
		$canView   = current_user_can( QevixShield_Settings::VIEW_CAP );
		$canManage = current_user_can( QevixShield_Settings::CAP );

		// My Activity — the current user's own rows. Everyone who can open the
		// Dashboard gets this; for users without VIEW_CAP it's the only section
		// shown. The `account` arg also matches username-only rows (a failed
		// login is recorded before authentication, so its user_id is 0).
		$currentUser  = wp_get_current_user();
		$myArgs       = array(
			'account'   => array(
				'id'    => (int) $currentUser->ID,
				'login' => (string) $currentUser->user_login,
			),
			// Today only (site-local, matching log()'s current_time stamps) —
			// the Dashboard answers "what happened on my account today?"; the
			// retention window's full history stays on the Audit Log screen.
			'date_from' => current_time( 'Y-m-d' ),
			'paged'     => isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized.
			'per_page'  => 20,
		);
		$myRows       = $this->audit_log->query( $myArgs );
		$myTotal      = $this->audit_log->count( $myArgs );
		$myTotalPages = (int) ceil( $myTotal / $myArgs['per_page'] );

		// Site-wide data (stat cards, pro widgets, the Recent Activity feed) is
		// only gathered for monitoring roles. Which of the two activity tabs is
		// open defaults to Recent Activity.
		$activityTab     = 'recent';
		$since_24h       = '';
		$failed_24h      = 0;
		$success_24h     = 0;
		$lockouts_24h    = 0;
		$recent          = array();
		$sessions_count  = 0;
		$pro_widgets     = array();
		$pro_widget_data = array();

		if ( $canView ) {
			$activityTab = ( isset( $_GET['activity'] ) && 'mine' === sanitize_key( wp_unslash( $_GET['activity'] ) ) ) ? 'mine' : 'recent'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized.

			// Site-local (matches date_from above and log()'s current_time stamps);
			// a UTC boundary would miscount around midnight on non-UTC sites.
			$since_24h    = gmdate( 'Y-m-d', current_time( 'timestamp' ) - DAY_IN_SECONDS );
			$failed_24h   = $this->audit_log->count( array( 'action' => 'login_failed', 'date_from' => $since_24h ) );
			$success_24h  = $this->audit_log->count( array( 'action' => 'login_success', 'date_from' => $since_24h ) );
			$lockouts_24h = $this->audit_log->count( array( 'action' => 'ip_locked_out', 'date_from' => $since_24h ) );

			// Recent Activity is a notable-events digest, not a log preview:
			// only warning/critical rows, with consecutive repeats of the same
			// event collapsed (a brute-force wave reads as one line, not 60).
			// The full record — all severities, filters, export — is the Audit Log
			// screen; keeping the two perspectives distinct is deliberate.
			$recent = self::digest_events(
				$this->audit_log->query(
					array(
						'severity' => array( 'warning', 'critical' ),
						'per_page' => 60,
						'paged'    => 1,
					)
				)
			);

			$sessions_count = 1;
			if ( function_exists( 'wp_get_session_token' ) && is_user_logged_in() ) {
				$manager        = WP_Session_Tokens::get_instance( get_current_user_id() );
				$sessions_count = count( $manager->get_all() );
			}

			$is_pro = (bool) apply_filters( 'qevix_shield_is_pro_active', false );

			// The six analytics cards are computed here, from THIS plugin's own
			// data (the audit log, the malware-scan option, the settings). They
			// are shown filled on every tier — nothing on this dashboard is
			// locked behind a licence. Pro may still ENRICH two of them
			// (Security Score and Password Policy pick up Pro's extra rules)
			// through the filter below, but the free values stand on their own.
			$pro_widgets     = self::pro_widget_defs();
			$pro_widget_data = $this->compute_widgets( $this->audit_log, $since_24h );
			$pro_widget_data = (array) apply_filters(
				'qevix_shield_dashboard_pro_widgets',
				$pro_widget_data,
				array(
					'audit_log' => $this->audit_log,
					'since_24h' => $since_24h,
					'is_pro'    => $is_pro,
				)
			);
		}

		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/dashboard.php';
	}

	/**
	 * Collapses a newest-first list of log rows into digest groups: a run of
	 * consecutive rows sharing action/user/IP/severity becomes one entry with
	 * a repeat count and the most recent timestamp. Only consecutive rows
	 * merge — two attack waves separated by other events stay two lines.
	 *
	 * @param object[] $rows Log rows, newest first (query() order).
	 * @param int      $max  Maximum number of groups returned.
	 * @return object[] Groups: action, username, ip, severity, count, last_time.
	 */
	public static function digest_events( array $rows, $max = 8 ) {
		$groups  = array();
		$current = null;

		foreach ( $rows as $row ) {
			$key = $row->action . '|' . $row->username . '|' . $row->ip . '|' . $row->severity;

			if ( $current && $current->key === $key ) {
				$current->count++;
				continue;
			}
			if ( count( $groups ) >= $max ) {
				break;
			}
			$current = (object) array(
				'key'       => $key,
				'action'    => $row->action,
				'username'  => $row->username,
				'ip'        => $row->ip,
				'severity'  => $row->severity,
				'count'     => 1,
				'last_time' => $row->timestamp,
			);
			$groups[] = $current;
		}

		return $groups;
	}

	/**
	 * Canonical pro dashboard widgets: key => [label, icon]. Shared by the free
	 * view and the pro data provider, which keys its values off
	 * these same slugs. Change the set here, not in two places.
	 *
	 * @return array<string,array{label:string,icon:string}>
	 */
	/**
	 * Compute the six analytics cards from this plugin's own data. Every value
	 * here is derived from the audit log, the malware-scan result option, or the
	 * settings this plugin owns — so the cards are never locked. Pro's filter may
	 * later enrich Security Score / Password Policy with its own extra rules;
	 * absent Pro, those checks are simply off, which is the truth.
	 *
	 * @param QevixShield_Audit_Log $audit
	 * @param string                $since24h  Y-m-d cutoff for 24h windows.
	 * @return array<string,array>
	 */
	private function compute_widgets( $audit, $since24h ) {
		$s = new QevixShield_Settings();

		// -- Threat Summary: blocked requests in the last 24h --
		$blocked = $audit ? (int) $audit->count( array( 'status' => 'blocked', 'date_from' => $since24h ) ) : 0;
		$widgets['threat_summary'] = array(
			'value'  => number_format_i18n( $blocked ),
			'sub'    => __( 'threats blocked (24h)', 'qevix-shield' ),
			'status' => $blocked > 0 ? 'warn' : 'good',
			'badge'  => true,
		);

		// -- XML-RPC Statistics: blocked vs allowed in 24h --
		if ( $audit ) {
			$xBlocked = (int) $audit->count( array( 'module' => 'xmlrpc', 'status' => 'blocked', 'date_from' => $since24h ) );
			$xAllowed = (int) $audit->count( array( 'module' => 'xmlrpc', 'status' => 'allowed', 'date_from' => $since24h ) );
			$widgets['xmlrpc_stats'] = array(
				/* translators: %d: blocked count */
				'value'    => sprintf( __( '%d blocked', 'qevix-shield' ), $xBlocked ),
				/* translators: %d: allowed count */
				'sub'      => sprintf( __( '%d allowed (24h)', 'qevix-shield' ), $xAllowed ),
				'status'   => $xBlocked > 0 ? 'warn' : 'good',
				'progress' => array( $xBlocked, $xBlocked + $xAllowed ),
			);
		} else {
			$widgets['xmlrpc_stats'] = array(
				'value'  => __( 'No data', 'qevix-shield' ),
				'sub'    => __( 'enable XML-RPC logging', 'qevix-shield' ),
				'status' => 'neutral',
			);
		}

		// -- Malware Scan Status + Plugin Integrity: from the last scan result --
		$r        = get_option( 'qevix_shield_malware_results', array() );
		$r        = is_array( $r ) ? $r : array();
		$findings = isset( $r['findings'] ) ? (array) $r['findings'] : array();
		if ( empty( $r['time'] ) ) {
			$widgets['malware_status']   = array( 'value' => __( 'Never scanned', 'qevix-shield' ), 'sub' => __( 'Run a scan to check', 'qevix-shield' ), 'status' => 'warn', 'badge' => true );
			$widgets['plugin_integrity'] = array( 'value' => __( 'Not scanned', 'qevix-shield' ), 'sub' => __( 'Run a scan to verify', 'qevix-shield' ), 'status' => 'warn', 'badge' => true );
		} else {
			$when     = sprintf( /* translators: %s: human time diff */ __( 'last scan %s ago', 'qevix-shield' ), human_time_diff( (int) $r['time'], time() ) );
			$critical = isset( $r['counts']['critical'] ) ? (int) $r['counts']['critical'] : 0;
			$count    = count( $findings );
			$widgets['malware_status'] = $count > 0
				? array( 'value' => sprintf( /* translators: %s: number of findings */ _n( '%s issue', '%s issues', $count, 'qevix-shield' ), number_format_i18n( $count ) ), 'sub' => $when, 'status' => $critical > 0 ? 'bad' : 'warn', 'badge' => true )
				: array( 'value' => __( 'Clean', 'qevix-shield' ), 'sub' => $when, 'status' => 'good', 'badge' => true );

			$fileFindings = 0;
			foreach ( $findings as $f ) {
				if ( isset( $f['type'] ) && in_array( $f['type'], array( 'checksum', 'pattern' ), true ) ) {
					$fileFindings++;
				}
			}
			$widgets['plugin_integrity'] = $fileFindings > 0
				? array( 'value' => sprintf( /* translators: %s: number of flagged files */ _n( '%s flagged file', '%s flagged files', $fileFindings, 'qevix-shield' ), number_format_i18n( $fileFindings ) ), 'sub' => __( 'modified or suspicious', 'qevix-shield' ), 'status' => 'bad', 'badge' => true )
				: array( 'value' => __( 'Verified', 'qevix-shield' ), 'sub' => __( 'no file tampering found', 'qevix-shield' ), 'status' => 'good', 'badge' => true );
		}

		// -- Security Score: share of the hardening toggles that are on. Pro's
		//    own two checks (common-password, scheduled scan) are counted via
		//    the filter so an unlicensed site scores honestly without them. --
		$lpOn = (bool) $s->get( 'login_protection_enabled', false );
		$fsOn = (bool) $s->get( 'file_security_enabled', false );
		$checks = array(
			$fsOn && $s->get( 'firewall_enabled', false ),
			$fsOn && $s->get( 'block_sensitive_files', false ),
			$fsOn && $s->get( 'fs_block_direct_php', false ),
			$fsOn && $s->get( 'fs_disable_php_exec', false ),
			$fsOn && $s->get( 'hide_wp_version', false ),
			$fsOn && $s->get( 'block_author_enum', false ),
			$fsOn && $s->get( 'block_user_enum', false ),
			$lpOn && $s->get( 'honeypot_enabled', false ),
			(bool) $s->get( 'xmlrpc_enabled', false ),
			(bool) $s->get( 'hide_login_enabled', false ),
			(bool) $s->get( 'alerts_enabled', false ),
			(bool) $s->get( 'recaptcha_enabled', false ),
			(bool) $s->get( 'twofa_enabled', false ),
		);
		$widgets['security_score']  = self::score_card( array_map( 'boolval', $checks ) );

		// -- Password Policy Status: share of the free password rules that are on --
		$min = (int) $s->get( 'pwd_min_length', 0 );
		$pw  = array(
			$min >= 12,
			(bool) $s->get( 'pwd_require_upper', false ),
			(bool) $s->get( 'pwd_require_number', false ),
			(bool) $s->get( 'pwd_require_special', false ),
			(bool) $s->get( 'pwd_disallow_user_info', false ),
		);
		$widgets['password_policy'] = self::policy_card( array_map( 'boolval', $pw ), $min );

		return $widgets;
	}

	/** Security Score card from a list of booleans (share on → 0–100 + rating). */
	private static function score_card( array $checks ) {
		$total = count( $checks );
		$on    = count( array_filter( $checks ) );
		$score = $total ? (int) round( $on / $total * 100 ) : 0;
		if ( $score >= 80 ) {
			$label = __( 'Strong', 'qevix-shield' ); $status = 'good';
		} elseif ( $score >= 50 ) {
			$label = __( 'Moderate', 'qevix-shield' ); $status = 'warn';
		} else {
			$label = __( 'Weak', 'qevix-shield' ); $status = 'bad';
		}
		return array(
			'value'    => $score . '/100',
			/* translators: 1: rating word, 2: enabled count, 3: total count */
			'sub'      => sprintf( __( '%1$s · %2$d of %3$d protections on', 'qevix-shield' ), $label, $on, $total ),
			'status'   => $status,
			'progress' => array( $score, 100 ),
		);
	}

	/** Password Policy card from a list of booleans + the minimum length. */
	private static function policy_card( array $checks, $min ) {
		$total = count( $checks );
		$on    = count( array_filter( $checks ) );
		if ( $on >= (int) ceil( $total * 0.75 ) ) {
			$label = __( 'Strong', 'qevix-shield' ); $status = 'good';
		} elseif ( $on >= (int) ceil( $total * 0.4 ) ) {
			$label = __( 'Moderate', 'qevix-shield' ); $status = 'warn';
		} else {
			$label = __( 'Basic', 'qevix-shield' ); $status = 'bad';
		}
		return array(
			'value'    => $label,
			/* translators: 1: minimum length, 2: enabled rule count, 3: total rules */
			'sub'      => sprintf( __( 'min %1$d chars · %2$d/%3$d rules on', 'qevix-shield' ), (int) $min, $on, $total ),
			'status'   => $status,
			'progress' => array( $on, $total ),
		);
	}

	public static function pro_widget_defs() {
		// 'page' is the admin submenu the whole (unlocked) card links to.
		return array(
			'security_score'   => array( 'label' => __( 'Security Score', 'qevix-shield' ),        'icon' => 'dashicons-shield',        'page' => 'qevix-shield-settings' ),
			'threat_summary'   => array( 'label' => __( 'Threat Summary', 'qevix-shield' ),        'icon' => 'dashicons-warning',       'page' => 'qevix-shield-logs' ),
			'malware_status'   => array( 'label' => __( 'Malware Scan Status', 'qevix-shield' ),   'icon' => 'dashicons-search',        'page' => 'qevix-shield-malware' ),
			'password_policy'  => array( 'label' => __( 'Password Policy Status', 'qevix-shield' ), 'icon' => 'dashicons-admin-network', 'page' => 'qevix-shield-password-security' ),
			'plugin_integrity' => array( 'label' => __( 'Plugin Integrity', 'qevix-shield' ),      'icon' => 'dashicons-admin-plugins', 'page' => 'qevix-shield-malware' ),
			'xmlrpc_stats'     => array( 'label' => __( 'XML-RPC Statistics', 'qevix-shield' ),    'icon' => 'dashicons-rest-api',      'page' => 'qevix-shield-xmlrpc' ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* WordPress Dashboard widget (alongside At a Glance / Site Health)     */
	/* ------------------------------------------------------------------ */

	/**
	 * Hooked on `wp_dashboard_setup`: adds a "Qevix Shield — Site Security" widget
	 * to the main WordPress Dashboard, so the security posture and the next
	 * things to switch on are visible the moment an admin signs in — the same
	 * spot as At a Glance and Site Health Status. Shown to anyone who can view
	 * Qevix Shield; the change-a-setting nudges are limited to managers (CAP).
	 */
	public function register_dashboard_widget() {
		if ( ! current_user_can( QevixShield_Settings::VIEW_CAP ) ) {
			return;
		}
		wp_add_dashboard_widget( 'qevix_shield_status', __( 'Qevix Shield — Site Security', 'qevix-shield' ), array( $this, 'render_dashboard_widget' ) );
	}

	/** Renders the widget: last-24h blocked-threat count + actionable "turn this on" nudges. */
	public function render_dashboard_widget() {
		$settings  = new QevixShield_Settings();
		$canManage = current_user_can( QevixShield_Settings::CAP );
		$since     = gmdate( 'Y-m-d', current_time( 'timestamp' ) - DAY_IN_SECONDS );
		$blocked   = $this->audit_log->count( array( 'status' => 'blocked', 'date_from' => $since ) );
		$isPro     = (bool) apply_filters( 'qevix_shield_is_pro_active', false );

		// One nudge per key protection that is currently OFF, each linking to the
		// tab that switches it on. Managers only — they're the ones who can act.
		$recs = array();
		if ( $canManage ) {
			$tab = static function ( $slug ) { return admin_url( 'admin.php?page=qevix-shield-settings&tab=' . $slug ); };
			if ( ! $settings->get( 'hide_login_enabled', false ) ) {
				$recs[] = array( 'text' => __( 'Your login page is the public wp-login.php — hide it behind a secret address to dodge automated attacks.', 'qevix-shield' ), 'cta' => __( 'Hide login page', 'qevix-shield' ), 'url' => $tab( 'hide-login' ) );
			}
			if ( 'off' === (string) $settings->get( 'xmlrpc_mode', 'off' ) ) {
				$recs[] = array( 'text' => __( 'XML-RPC is open — a common brute-force and pingback target. Restrict or disable it.', 'qevix-shield' ), 'cta' => __( 'Secure XML-RPC', 'qevix-shield' ), 'url' => $tab( 'xmlrpc' ) );
			}
			if ( ! $settings->get( 'firewall_enabled', true ) ) {
				$recs[] = array( 'text' => __( 'The firewall is turned off — turn it on to block SQL injection, XSS, and vulnerability-scanner traffic.', 'qevix-shield' ), 'cta' => __( 'Enable firewall', 'qevix-shield' ), 'url' => $tab( 'file-security' ) );
			}
			if ( ! $settings->get( 'honeypot_enabled', true ) ) {
				$recs[] = array( 'text' => __( 'The login honeypot is off — turn it on to silently catch login bots.', 'qevix-shield' ), 'cta' => __( 'Enable honeypot', 'qevix-shield' ), 'url' => $tab( 'login-protection' ) );
			}
			if ( ! $settings->get( 'block_sensitive_files', true ) ) {
				$recs[] = array( 'text' => __( 'Sensitive files (.env, .git, wp-config.php) are reachable over the web — turn on File Security.', 'qevix-shield' ), 'cta' => __( 'Protect files', 'qevix-shield' ), 'url' => $tab( 'file-security' ) );
			}

			/**
			 * Pro appends its own nudges (2FA, reCAPTCHA, scheduled scans).
			 * Each entry: array{ text:string, cta:string, url:string }.
			 *
			 * @param array $recs  Recommendations gathered so far.
			 * @param bool  $isPro Whether a valid Pro license is active.
			 */
			$recs = (array) apply_filters( 'qevix_shield_dashboard_recommendations', $recs, $isPro );

			if ( ! $isPro ) {
				// Land on the in-plugin Pro / License tab (not straight to an
				// external site) so the user sees what the add-on actually adds
				// before any buy link. NOTE: name only capabilities this plugin
				// does NOT implement — two-factor and reCAPTCHA are fully
				// included here, so they must never appear in this sentence.
				$recs[] = array( 'text' => __( 'Malware quarantine, scheduled scans, and SMS or webhook alerts are available with Qevix Shield Pro.', 'qevix-shield' ), 'cta' => __( 'See what Pro adds', 'qevix-shield' ), 'url' => $tab( 'license' ) );
			}
		}
		$recs = array_slice( $recs, 0, 4 );
		?>
		<div class="qevix-shield-dw">
			<p class="qevix-shield-dw-head">
				<span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
				<span>
					<?php
					if ( $blocked > 0 ) {
						printf(
							wp_kses( /* translators: %d: number of blocked security events */ _n( '<strong>%d</strong> threat blocked in the last 24 hours.', '<strong>%d</strong> threats blocked in the last 24 hours.', $blocked, 'qevix-shield' ), array( 'strong' => array() ) ),
							(int) $blocked
						);
					} else {
						esc_html_e( 'No threats blocked in the last 24 hours — your defenses are holding.', 'qevix-shield' );
					}
					?>
				</span>
			</p>

			<?php if ( $canManage && ! empty( $recs ) ) : ?>
				<p class="qevix-shield-dw-sub"><strong><?php esc_html_e( 'Recommended next steps', 'qevix-shield' ); ?></strong></p>
				<ul class="qevix-shield-dw-recs">
					<?php foreach ( $recs as $r ) : ?>
						<li>
							<span class="dashicons dashicons-warning" aria-hidden="true"></span>
							<span><?php echo esc_html( $r['text'] ); ?>
								<a href="<?php echo esc_url( $r['url'] ); ?>"<?php echo empty( $r['ext'] ) ? '' : ' target="_blank" rel="noopener"'; ?>><?php echo esc_html( $r['cta'] ); ?> &rsaquo;</a>
							</span>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php elseif ( $canManage ) : ?>
				<p class="qevix-shield-dw-ok"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span> <?php esc_html_e( 'Your key protections are all switched on. Nicely secured.', 'qevix-shield' ); ?></p>
			<?php endif; ?>

			<p class="qevix-shield-dw-foot">
				<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=' . QevixShield_Menu::PARENT_SLUG ) ); ?>"><?php esc_html_e( 'Open Qevix Shield', 'qevix-shield' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Enqueue the widget's stylesheet on the main Dashboard (index.php), which
	 * doesn't load Qevix Shield's admin.css — the menu only enqueues that on
	 * qevix-shield* screens. Only for users who actually see the widget (VIEW_CAP).
	 * Hooked on admin_enqueue_scripts.
	 */
	public function enqueue_dashboard_assets( $hook ) {
		if ( 'index.php' !== $hook || ! current_user_can( QevixShield_Settings::VIEW_CAP ) ) {
			return;
		}
		$rel   = 'assets/css/dashboard-widget.css';
		$mtime = @filemtime( QEVIX_SHIELD_PLUGIN_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- @ tolerates a missing asset file; a falsy mtime falls back to the plugin version.
		$ver   = $mtime ? QEVIX_SHIELD_VERSION . '.' . $mtime : QEVIX_SHIELD_VERSION;
		wp_enqueue_style( 'qevix-shield-dashboard-widget', QEVIX_SHIELD_PLUGIN_URL . $rel, array(), $ver );
	}
}
