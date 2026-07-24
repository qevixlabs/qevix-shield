<?php
/**
 * Top-level "Qevix Shield Pro" menu, built entirely from the
 * `qevix_shield_admin_pages` filter — the pro plugin, or later free-tier
 * phases, add pages through that same filter without this class changing.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Menu {

	const PARENT_SLUG = 'qevix-shield';

	/** @var QevixShield_Dashboard */
	private $dashboard;

	/** @var QevixShield_Settings */
	private $settings;

	/** @var QevixShield_Audit_Log */
	private $audit_log;

	/** @var QevixShield_Sessions */
	private $sessions;

	/** @var QevixShield_Malware_Scanner */
	private $scanner;

	/** @var QevixShield_File_Security */
	private $file_security;

	public function __construct( QevixShield_Dashboard $dashboard, QevixShield_Settings $settings, QevixShield_Audit_Log $auditLog, QevixShield_Sessions $sessions, QevixShield_Malware_Scanner $scanner, QevixShield_File_Security $fileSecurity ) {
		$this->dashboard     = $dashboard;
		$this->settings      = $settings;
		$this->audit_log     = $auditLog;
		$this->sessions      = $sessions;
		$this->scanner       = $scanner;
		$this->file_security = $fileSecurity;
	}

	/**
	 * Hooked on `qevix_shield_admin_pages` at priority 10 to seed the free
	 * plugin's own pages before anything else (pro) is appended.
	 */
	public function register_admin_pages( $pages ) {
		$pages[] = array(
			'slug'       => self::PARENT_SLUG,
			'page_title' => __( 'Qevix Shield Dashboard', 'qevix-shield' ),
			'menu_title' => __( 'Dashboard', 'qevix-shield' ),
			// Any logged-in user can open the Dashboard: monitoring roles
			// (General tab `view_roles`) get the full dashboard, while everyone
			// else sees only their own recent activity. The render method gates
			// the site-wide data on VIEW_CAP.
			'capability' => 'read',
			'callback'   => array( $this->dashboard, 'render' ),
			'position'   => 10,
		);
		// Settings is deliberately kept as the SECOND submenu (right after
		// Dashboard); feature pages come after it.
		$pages[] = array(
			'slug'       => 'qevix-shield-settings',
			'page_title' => __( 'Qevix Shield Settings', 'qevix-shield' ),
			'menu_title' => __( 'Settings', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_settings_page' ),
			'position'   => 15,
		);
		$pages[] = array(
			'slug'       => 'qevix-shield-login-protection',
			'page_title' => __( 'Qevix Shield Login Protection', 'qevix-shield' ),
			'menu_title' => __( 'Login Protection', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_login_protection_page' ),
			'tab'        => 'login-protection',
			'position'   => 20,
		);
		// Password Security sits right after Login Protection.
		$pages[] = array(
			'slug'       => 'qevix-shield-password-security',
			'page_title' => __( 'Qevix Shield Password Security', 'qevix-shield' ),
			'menu_title' => __( 'Password Security', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_password_security_page' ),
			'tab'        => 'password-security',
			'position'   => 22,
		);
		// File Security sits between XML-RPC Protection (26) and Notifications (30).
		$pages[] = array(
			'slug'       => 'qevix-shield-file-security',
			'page_title' => __( 'Qevix Shield File Security', 'qevix-shield' ),
			'menu_title' => __( 'File Security', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_file_security_page' ),
			'tab'        => 'file-security',
			'position'   => 28,
		);
		// Sessions sits between Notifications (30) and the Audit Log (34).
		$pages[] = array(
			'slug'       => 'qevix-shield-sessions',
			'page_title' => __( 'Qevix Shield Sessions', 'qevix-shield' ),
			'menu_title' => __( 'Sessions', 'qevix-shield' ),
			'capability' => 'read', // Per-user: any logged-in user sees only their own sessions.
			'callback'   => array( $this, 'render_sessions_page' ),
			'tab'        => 'sessions',
			'position'   => 32,
		);
		// XML-RPC Protection submenu (its tab lives at position 26 too).
		$pages[] = array(
			'slug'       => 'qevix-shield-xmlrpc',
			'page_title' => __( 'Qevix Shield XML-RPC Protection', 'qevix-shield' ),
			'menu_title' => __( 'XML-RPC Protection', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_xmlrpc_page' ),
			'tab'        => 'xmlrpc',
			'position'   => 26,
		);
		// Malware Scanner sits between Password Security (22) and XML-RPC (26).
		$pages[] = array(
			'slug'       => 'qevix-shield-malware',
			'page_title' => __( 'Qevix Shield Malware Scanner', 'qevix-shield' ),
			'menu_title' => __( 'Malware Scanner', 'qevix-shield' ),
			// VIEW_CAP: scan RESULTS are readable by read-only roles; the view
			// hides the settings form + Run Scan for them, and the save/scan
			// handlers still require CAP.
			'capability' => QevixShield_Settings::VIEW_CAP,
			'callback'   => array( $this, 'render_malware_page' ),
			'tab'        => 'malware',
			'position'   => 24,
		);
		// Notifications sits right after File Security (free owns email alerts;
		// pro injects SMS/webhook/severity-threshold fields here later).
		$pages[] = array(
			'slug'       => 'qevix-shield-notifications',
			'page_title' => __( 'Qevix Shield Notifications', 'qevix-shield' ),
			'menu_title' => __( 'Notifications', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_notifications_page' ),
			'tab'        => 'notifications',
			'position'   => 30,
		);
		$pages[] = array(
			'slug'       => 'qevix-shield-logs',
			'page_title' => __( 'Qevix Shield Audit Log', 'qevix-shield' ),
			'menu_title' => __( 'Audit Log', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_logs_page' ),
			// Right after Sessions (32), before Pro/License (1000) —
			// second-last, same as its tab (see register_settings_tabs()).
			'tab'        => 'logs',
			'position'   => 34,
		);
		return $pages;
	}

	/**
	 * Free plugin's own Settings tabs — the companion filter to
	 * qevix_shield_admin_pages. Pro modules add tabs onto this same filter so the
	 * Settings page becomes a shared, extensible tabbed surface without this
	 * class knowing about them.
	 */
	public function register_settings_tabs( $tabs ) {
		$tabs[] = array(
			'slug'       => 'general',
			'label'      => __( 'General', 'qevix-shield' ),
			'render'     => array( $this->settings, 'render_general_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 10,
		);
		$tabs[] = array(
			'slug'       => 'login-protection',
			'label'      => __( 'Login Protection', 'qevix-shield' ),
			'render'     => array( $this->settings, 'render_login_protection_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 20,
		);
		$tabs[] = array(
			'slug'       => 'password-security',
			'label'      => __( 'Password Security', 'qevix-shield' ),
			'render'     => array( $this->settings, 'render_password_security_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 22,
		);
		// File Security sits between XML-RPC Protection (26) and Notifications (30).
		$tabs[] = array(
			'slug'       => 'file-security',
			'label'      => __( 'File Security', 'qevix-shield' ),
			'render'     => array( $this->file_security, 'render_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 28,
		);
		// Sessions sits between Notifications (30) and the Audit Log (34).
		$tabs[] = array(
			'slug'       => 'sessions',
			'label'      => __( 'Sessions', 'qevix-shield' ),
			'render'     => array( $this->sessions, 'render_section' ),
			'capability' => 'read', // Any logged-in user can see their own sessions.
			'position'   => 32,
		);
		// Hide Admin Panel is the SECOND tab, right after General (10).
		$tabs[] = array(
			'slug'       => 'hide-login',
			'label'      => __( 'Hide Admin Panel', 'qevix-shield' ),
			'render'     => array( $this->settings, 'render_hide_login_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 12,
		);
		// XML-RPC Protection right after Malware Scanner (24).
		$tabs[] = array(
			'slug'       => 'xmlrpc',
			'label'      => __( 'XML-RPC Protection', 'qevix-shield' ),
			'render'     => array( $this->settings, 'render_xmlrpc_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 26,
		);
		// Malware Scanner sits between Password Security (22) and XML-RPC (26).
		$tabs[] = array(
			'slug'       => 'malware',
			'label'      => __( 'Malware Scanner', 'qevix-shield' ),
			'render'     => array( $this->scanner, 'render_section' ),
			// VIEW_CAP: results readable by read-only roles; the view hides the
			// settings form + Run Scan unless the viewer holds CAP.
			'capability' => QevixShield_Settings::VIEW_CAP,
			'position'   => 24,
		);
		// Notifications right after File Security (email alerts are free;
		// pro adds SMS/webhook channels + severity threshold by field injection).
		$tabs[] = array(
			'slug'       => 'notifications',
			'label'      => __( 'Notifications', 'qevix-shield' ),
			'render'     => array( $this->settings, 'render_notifications_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 30,
		);
		// The Audit Log sits second-last (position 34, right after Sessions at 32,
		// before Pro/License at 1000) — same relative spot as its standalone
		// submenu. Content renders inside the shared tab body, not a
		// separate page-chrome view.
		$tabs[] = array(
			'slug'       => 'logs',
			'label'      => __( 'Audit Log', 'qevix-shield' ),
			'render'     => array( $this, 'render_logs_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 34,
		);
		return $tabs;
	}

	/**
	 * Echo a "?" help icon whose popover explains the adjacent option
	 * (what it does, an example, the consequence). Used next to field labels
	 * on every settings tab — the PRO views call it too, so it lives here in
	 * the free plugin, which pro always depends on.
	 *
	 * Deliberately spans, not a <button>: several tabs render their pro
	 * fields inside `<fieldset disabled>`, which would disable a real button
	 * and make the help unreachable exactly where users need it most.
	 * assets/js/help-tips.js adds the click/keyboard toggle; CSS alone covers
	 * hover/focus.
	 *
	 * @param string $text Explanation. Limited inline HTML allowed
	 *                     (code/strong/em/br).
	 */
	public static function help_tip( $text ) {
		$allowed = array(
			'code'   => array(),
			'strong' => array(),
			'em'     => array(),
			'br'     => array(),
		);
		echo '<span class="qevix-shield-help">'
			. '<span class="qevix-shield-help-icon" role="button" tabindex="0" aria-expanded="false" aria-label="' . esc_attr__( 'More information', 'qevix-shield' ) . '">?</span>'
			. '<span class="qevix-shield-help-pop" role="tooltip">' . wp_kses( $text, $allowed ) . '</span>'
			. '</span>';
	}

	/**
	 * Inline dependency warning shown under a control whose setting is enabled
	 * but its required companion value is missing or another setting it needs is
	 * off (e.g. "Hide Login on, but no slug"; "reCAPTCHA on, but no keys"). A
	 * non-blocking hint — the config still saves; this just tells the admin why
	 * it won't take effect yet. Static so PRO views (which render fields inside
	 * free-owned forms) call it too, like help_tip(). Pass an already-translated
	 * message; limited inline HTML (code/strong/em) is allowed.
	 *
	 * @param string $message Already-translated warning text.
	 */
	public static function dependency_notice( $message ) {
		$allowed = array(
			'code'   => array(),
			'strong' => array(),
			'em'     => array(),
		);
		echo '<div class="notice notice-warning inline qevix-shield-dep-notice"><p>'
			. '<span class="dashicons dashicons-warning" aria-hidden="true"></span> '
			. wp_kses( $message, $allowed )
			. '</p></div>';
	}

	/**
	 * Sessions-style locked-feature card — the single unlicensed presentation
	 * (replaces the older disabled-fieldset previews):
	 * a white .card with a lock heading ("<Title> — Pro"), a bullet list of
	 * what the pro feature does, and the two standard CTAs. Rendered wherever
	 * the license is not valid (free tier, not activated, expired, revoked)
	 * INSTEAD of the feature's fields. Static so PRO views call it too — like
	 * help_tip(), it lives here in the free plugin, which pro always depends
	 * on. The disabled-fieldset treatment remains only for the licensed
	 * viewer WITHOUT manage_options (read-only preview of real settings).
	 *
	 * @param string   $title    Feature name, without the "— Pro" suffix.
	 * @param string   $intro    One-line lead-in above the bullet list.
	 * @param string[] $features Already-translated bullet strings.
	 */
	public static function render_pro_upsell( $title, $intro, array $features ) {
		$buyUrl = esc_url( apply_filters( 'qevix_shield_buy_url', QEVIX_SHIELD_BUY_URL ) );
		?>
		<div class="card qevix-shield-locked qevix-shield-pro-preview qevix-shield-panel">
			<h2>
				<span class="dashicons dashicons-lock"></span>
				<?php echo esc_html( $title ); ?> &mdash; <?php esc_html_e( 'Pro', 'qevix-shield' ); ?>
			</h2>
			<p><?php echo esc_html( $intro ); ?></p>
			<ul class="qevix-shield-disc-list">
				<?php foreach ( $features as $feature ) : ?>
					<li><?php echo esc_html( $feature ); ?></li>
				<?php endforeach; ?>
			</ul>
			<p>
				<a href="<?php echo $buyUrl; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- already esc_url'd. ?>" class="button button-primary" target="_blank" rel="noopener">
					<?php esc_html_e( 'Get Qevix Shield Pro', 'qevix-shield' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=qevix-shield-settings&tab=license' ) ); ?>" class="button">
					<?php esc_html_e( 'Already purchased? Enter license', 'qevix-shield' ); ?>
				</a>
			</p>
		</div>
		<?php
	}

	/**
	 * The full Qevix Shield Pro feature list as bullet points — shown on the
	 * Qevix Shield Pro tab whenever Pro is not active (not installed, or installed
	 * but expired / revoked / not yet activated). Aggregates what each per-tab
	 * teaser card advertises so the whole offer is visible on one screen. Static
	 * and here in the free menu class so the pro License view renders the same
	 * list; each feature name is emphasised with an inline <strong>.
	 *
	 * Grouped by what the buyer gets, not by module — the free tier already
	 * DETECTS and hardens; Pro is about acting on what's found, running it
	 * hands-off, and going deeper. Every bullet must name something the Pro
	 * plugin implements ITSELF (wp.org Guideline 5, 2026-07-23) — never a
	 * capability that already ships in this free plugin (2FA incl. per-role
	 * enforcement, reCAPTCHA v2+v3 with threshold/email-fallback on all three
	 * login forms, backup / custom protected-file rules are all free).
	 */
	public static function render_pro_feature_list() {
		$groups = array(
			__( 'Remediation & response', 'qevix-shield' ) => array(
				__( '<strong>Quarantine &amp; delete</strong> infected files, with a restorable quarantine store', 'qevix-shield' ),
				__( '<strong>Advanced login blocking</strong> — permanent IP blacklist, user-agent filtering, auto-blacklist for repeat offenders, and CIDR whitelist', 'qevix-shield' ),
				__( '<strong>Session management</strong> — view and revoke logins across every user, force logout, and idle timeout', 'qevix-shield' ),
				__( '<strong>Granular XML-RPC control</strong> — authenticated-only, a method allowlist, or trusted IPs only', 'qevix-shield' ),
			),
			__( 'Deeper protection', 'qevix-shield' ) => array(
				__( '<strong>Full malware scanning</strong> — plugins, themes, and uploads, plus a database scan for injected scripts and hidden iframes', 'qevix-shield' ),
				__( '<strong>Advanced password security</strong> — breached-password check, common-password blocklist, expiry, reuse prevention, and admin-forced reset', 'qevix-shield' ),
				__( '<strong>reCAPTCHA beyond wp-login</strong> — the WooCommerce my-account and checkout forms, plus hooks for any other plugin\'s custom forms', 'qevix-shield' ),
				__( '<strong>Trusted devices for two-factor</strong> — skip the code on browsers you approve, plus an emailed backup code for a lost device', 'qevix-shield' ),
			),
			__( 'Automation & alerts', 'qevix-shield' ) => array(
				__( '<strong>Scheduled scans</strong> — automatic daily or weekly malware sweeps', 'qevix-shield' ),
				__( '<strong>SMS &amp; webhook alerts</strong> — Twilio/WhatsApp, Slack, Discord, or any webhook, on top of email', 'qevix-shield' ),
			),
		);
		foreach ( $groups as $heading => $features ) {
			echo '<p class="qevix-shield-feature-group"><strong>' . esc_html( wp_strip_all_tags( $heading ) ) . '</strong></p>';
			echo '<ul class="qevix-shield-disc-list">';
			foreach ( $features as $feature ) {
				echo '<li>' . wp_kses( $feature, array( 'strong' => array() ) ) . '</li>';
			}
			echo '</ul>';
		}
	}

	/**
	 * Cache-busting asset version: the file's mtime rides along with the
	 * plugin version, so every edit to a CSS/JS file invalidates browser
	 * caches immediately (a bare QEVIX_SHIELD_VERSION served stale styles
	 * after in-place updates).
	 */
	private static function asset_ver( $rel ) {
		$mtime = @filemtime( QEVIX_SHIELD_PLUGIN_DIR . $rel );
		return $mtime ? QEVIX_SHIELD_VERSION . '.' . $mtime : QEVIX_SHIELD_VERSION;
	}

	public function enqueue_assets( $hook ) {
		if ( false === strpos( (string) $hook, 'qevix-shield' ) ) {
			return;
		}
		wp_enqueue_style( 'qevix-shield-admin', QEVIX_SHIELD_PLUGIN_URL . 'assets/css/admin.css', array(), self::asset_ver( 'assets/css/admin.css' ) );
		wp_enqueue_script( 'qevix-shield-help-tips', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/help-tips.js', array(), self::asset_ver( 'assets/js/help-tips.js' ), true );

		// Realtime log polling only when the Audit Log tab is the one actually
		// rendering: either its own standalone submenu with no ?tab= override
		// (mirrors render_tabbed_settings()'s forced-tab fallback), or any
		// entry point with ?tab=logs.
		$page     = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized.
		$tab      = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized.
		// reCAPTCHA "Test keys" preflight, on the reCAPTCHA tab only (same
		// entry-point logic as the Audit Log check below).
		if ( 'recaptcha' === $tab || ( 'qevix-shield-recaptcha' === $page && '' === $tab ) ) {
			wp_enqueue_script( 'qevix-shield-recaptcha-test', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/recaptcha-test.js', array(), self::asset_ver( 'assets/js/recaptcha-test.js' ), true );

			// The preflight tests the SAVED trio, so the script needs the saved
			// site key + version to load Google's api.js with (both public /
			// non-sensitive). The secret never leaves the server — only whether
			// one is stored, so the button can say "save keys first". The token
			// is the only thing the browser contributes; see ajax_test().
			$rcSettings = new QevixShield_Settings();
			wp_localize_script(
				'qevix-shield-recaptcha-test',
				'QevixShieldRecaptchaTest',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'qevix_shield_recaptcha_test' ),
					'savedSiteKey'   => trim( (string) $rcSettings->get( 'recaptcha_site_key', '' ) ),
					'savedVersion'   => 'v3' === apply_filters( 'qevix_shield_recaptcha_version', 'v2' ) ? 'v3' : 'v2',
					'hasSavedSecret' => '' !== trim( (string) $rcSettings->get( 'recaptcha_secret_key', '' ) ),
					'i18n'           => array(
						'test'      => __( 'Test keys', 'qevix-shield' ),
						'testing'   => __( 'Testing…', 'qevix-shield' ),
						'checking'  => __( 'Asking Google to check these keys…', 'qevix-shield' ),
						'tickBox'   => __( 'Tick the "I\'m not a robot" box below to finish the test. If you see an error inside it instead, these are not v2 keys.', 'qevix-shield' ),
						'needKeys'  => __( 'Save a Site Key and a Secret Key first, then test.', 'qevix-shield' ),
						'saveFirst' => __( 'Save your reCAPTCHA settings first, then press Test keys — the test checks the saved keys, not unsaved edits.', 'qevix-shield' ),
						'failed'    => __( 'The test could not be completed. Check the keys and try again.', 'qevix-shield' ),
					),
				)
			);
		}

		// Notifications tab: swap the gateway "Need help?" link with the
		// provider dropdown (Twilio vs WhatsApp).
		if ( 'notifications' === $tab || ( 'qevix-shield-notifications' === $page && '' === $tab ) ) {
			wp_enqueue_script( 'qevix-shield-notifications', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/notifications.js', array(), self::asset_ver( 'assets/js/notifications.js' ), true );
		}

		// Hide Login tab: reveal the custom-redirect URL field on demand.
		if ( 'hide-login' === $tab || ( 'qevix-shield-hide-login' === $page && '' === $tab ) ) {
			wp_enqueue_script( 'qevix-shield-hide-login', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/hide-login.js', array(), self::asset_ver( 'assets/js/hide-login.js' ), true );
		}

		// Password Security tab: sync each preset <select> with its number box.
		if ( 'password-security' === $tab || ( 'qevix-shield-password-security' === $page && '' === $tab ) ) {
			wp_enqueue_script( 'qevix-shield-password-security', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/password-security.js', array(), self::asset_ver( 'assets/js/password-security.js' ), true );
		}

		$logsOpen = ( 'logs' === $tab ) || ( 'qevix-shield-logs' === $page && '' === $tab );
		if ( $logsOpen ) {
			wp_enqueue_script( 'qevix-shield-logs-realtime', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/logs-realtime.js', array(), self::asset_ver( 'assets/js/logs-realtime.js' ), true );
			wp_localize_script(
				'qevix-shield-logs-realtime',
				'QevixShieldLogs',
				array(
					'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
					'nonce'    => wp_create_nonce( 'qevix_shield_poll_logs' ),
					'interval' => 10000,
					'filters'  => array(
						's'             => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
						'filter_action' => isset( $_GET['filter_action'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_action'] ) ) : '',
						'severity'      => isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '',
						'module'        => isset( $_GET['module'] ) ? sanitize_key( wp_unslash( $_GET['module'] ) ) : '',
					),
				)
			);
		}

		// The Dashboard widget cards are pure CSS (count text + CSS progress
		// bars); no chart JS is enqueued here.
	}

	public function add_menu() {
		$pages = (array) apply_filters( 'qevix_shield_admin_pages', array() );
		if ( empty( $pages ) ) {
			return;
		}

		$pages = self::sort_by_position( self::dedupe_by_slug( $pages ) );

		$is_pro_active = (bool) apply_filters( 'qevix_shield_is_pro_active', false );

		self::maybe_highlight_tab_submenu( $pages );

		$first = array_shift( $pages );

		// One fixed brand in every tier: "Qevix Shield". The menu is the free
		// plugin's (it owns add_menu_page; Pro only adds tabs), so it carries the
		// free plugin's real name — never "Pro", which would be misleading with
		// no Pro installed AND would move/rename the nav item mid-use each time a
		// license activates or lapses. Pro status is shown via the lock badges
		// and the Pro/License tab, not by renaming the menu.
		add_menu_page(
			__( 'QevixShield', 'qevix-shield' ),
			__( 'QevixShield', 'qevix-shield' ),
			$first['capability'],
			self::PARENT_SLUG,
			$first['callback'],
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			self::PARENT_SLUG,
			$first['page_title'],
			self::maybe_lock_title( $first, $is_pro_active ),
			$first['capability'],
			self::PARENT_SLUG,
			$first['callback']
		);

		foreach ( $pages as $page ) {
			add_submenu_page(
				self::PARENT_SLUG,
				$page['page_title'],
				self::maybe_lock_title( $page, $is_pro_active ),
				$page['capability'],
				$page['slug'],
				$page['callback']
			);
		}
	}

	/**
	 * The shared tabbed Settings screen is reachable from several left-nav
	 * submenu entries (Login Protection, Password Security, ...) as well as
	 * "Settings" itself — every entry point calls the same
	 * `render_tabbed_settings()`. WP's default highlighting only matches
	 * `$_GET['page']`, so switching tabs on that shared screen would
	 * otherwise leave whichever submenu slug got you there (or "Settings")
	 * highlighted forever, regardless of which tab is actually open.
	 *
	 * Override `$submenu_file` to track the ACTIVE TAB instead: a tab with
	 * its own submenu (built from each page's `tab` key, e.g.
	 * `login-protection` → `qevix-shield-login-protection`) highlights that
	 * submenu; a tab with none (General, Hide Admin Panel) falls back to
	 * "Settings", since that's the only submenu that owns it.
	 */
	private static function maybe_highlight_tab_submenu( array $pages ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized.
		if ( ! isset( $_GET['page'], $_GET['tab'] ) || 0 !== strpos( (string) wp_unslash( $_GET['page'] ), 'qevix-shield' ) ) {
			return;
		}

		$tab = sanitize_key( wp_unslash( $_GET['tab'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin view state, no data mutation; input is sanitized.

		$map = array();
		foreach ( $pages as $page ) {
			if ( ! empty( $page['tab'] ) ) {
				$map[ $page['tab'] ] = $page['slug'];
			}
		}

		$GLOBALS['submenu_file'] = isset( $map[ $tab ] ) ? $map[ $tab ] : 'qevix-shield-settings';
	}

	/**
	 * Appends a lock dashicon to a submenu title when the item is a pro feature
	 * and pro isn't active — so free users see every pro menu marked locked.
	 */
	private static function maybe_lock_title( array $page, $is_pro_active ) {
		$title = $page['menu_title'];
		if ( ! empty( $page['pro'] ) && ! $is_pro_active ) {
			$title .= ' <span class="dashicons dashicons-lock" style="font-size:15px;width:15px;height:15px;vertical-align:text-top;opacity:.7;"></span>';
		}
		return $title;
	}

	/** Collapse duplicate slugs, preferring the real (non-placeholder) entry. */
	public static function dedupe_by_slug( array $items ) {
		$bySlug = array();
		foreach ( $items as $item ) {
			$slug = isset( $item['slug'] ) ? $item['slug'] : '';
			if ( '' === $slug ) {
				$bySlug[] = $item;
				continue;
			}
			// Keep the first real entry; a placeholder never overrides a real one.
			if ( ! isset( $bySlug[ $slug ] ) || ( ! empty( $bySlug[ $slug ]['placeholder'] ) && empty( $item['placeholder'] ) ) ) {
				$bySlug[ $slug ] = $item;
			}
		}
		return array_values( $bySlug );
	}

	/**
	 * Site-wide warning while Safe Mode is active: every protection is paused,
	 * so this must be loud and must NOT be permanently dismissible — an admin
	 * has to keep remembering the site is unguarded until they remove the
	 * constant from wp-config.php.
	 */
	public function render_safe_mode_notice() {
		if ( ! QevixShield::is_safe_mode() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>' .
			esc_html__( 'Qevix Shield Safe Mode is active.', 'qevix-shield' ) . '</strong> ' .
			esc_html__( 'All Qevix Shield and Qevix Shield Pro protection is paused because QEVIX_SHIELD_SAFE_MODE is defined in wp-config.php. Your saved settings are preserved. Remove that line to restore protection.', 'qevix-shield' ) .
			'</p></div>';
	}

	/** The Settings submenu page callback. */
	public function render_settings_page() {
		self::render_tabbed_settings();
	}

	/** Login Protection submenu page: opens the shared tabbed view on that tab. */
	public function render_login_protection_page() {
		self::render_tabbed_settings( 'login-protection' );
	}

	/** Password Security submenu page: opens the shared tabbed view on that tab. */
	public function render_password_security_page() {
		self::render_tabbed_settings( 'password-security' );
	}

	/** File Security submenu page: opens the shared tabbed view on that tab. */
	public function render_file_security_page() {
		self::render_tabbed_settings( 'file-security' );
	}

	/** Sessions submenu page: opens the shared tabbed view on the Sessions tab. */
	public function render_sessions_page() {
		self::render_tabbed_settings( 'sessions' );
	}

	/** XML-RPC Protection submenu page: opens the shared tabbed view on that tab. */
	public function render_xmlrpc_page() {
		self::render_tabbed_settings( 'xmlrpc' );
	}

	/** Malware Scanner submenu page: opens the shared tabbed view on that tab. */
	public function render_malware_page() {
		self::render_tabbed_settings( 'malware' );
	}

	/** Notifications submenu page: opens the shared tabbed view on that tab. */
	public function render_notifications_page() {
		self::render_tabbed_settings( 'notifications' );
	}

	/**
	 * Renders the shared tabbed Settings UI. Static so pro submenu pages can
	 * delegate to it (a submenu click lands in the tabbed view rather than a
	 * separate screen). Tabs come from the `qevix_shield_settings_tabs` filter,
	 * are filtered by the viewer's capability, and pro tabs are badged.
	 *
	 * @param string|null $forcedTab Slug to pre-select (used by pro submenus).
	 */
	public static function render_tabbed_settings( $forcedTab = null ) {
		$allTabs = self::sort_by_position( self::dedupe_by_slug( (array) apply_filters( 'qevix_shield_settings_tabs', array() ) ) );

		// Only show tabs the current user is allowed to open.
		$tabs = array();
		foreach ( $allTabs as $tab ) {
			$cap = isset( $tab['capability'] ) ? $tab['capability'] : QevixShield_Settings::CAP;
			if ( current_user_can( $cap ) ) {
				$tabs[] = $tab;
			}
		}
		if ( empty( $tabs ) ) {
			return;
		}

		$slugs   = wp_list_pluck( $tabs, 'slug' );
		$default = $slugs[0];

		$active = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : null;
		if ( null === $active && null !== $forcedTab ) {
			$active = $forcedTab;
		}
		if ( ! in_array( $active, $slugs, true ) ) {
			$active = $default;
		}

		$is_pro_active = (bool) apply_filters( 'qevix_shield_is_pro_active', false );

		// Keep the tab strip on whatever submenu the user entered from, so the
		// left-nav highlight stays put while switching tabs.
		$currentPage = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'qevix-shield-settings';
		$base_url    = admin_url( 'admin.php?page=' . $currentPage );

		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings.php';
	}

	/** Stable sort by numeric 'position' (default 50). */
	public static function sort_by_position( array $items ) {
		usort(
			$items,
			static function ( $a, $b ) {
				$pa = isset( $a['position'] ) ? (int) $a['position'] : 50;
				$pb = isset( $b['position'] ) ? (int) $b['position'] : 50;
				return $pa <=> $pb;
			}
		);
		return $items;
	}

	/** Audit Log submenu page: opens the shared tabbed view on the Audit Log tab. */
	public function render_logs_page() {
		self::render_tabbed_settings( 'logs' );
	}

	/**
	 * Audit Log tab content — the actual query/render logic, shared by the Audit Log
	 * tab and (via render_logs_page() -> render_tabbed_settings()) its
	 * standalone submenu. Renders inside the shared tab body, not its own
	 * page chrome.
	 */
	public function render_logs_section() {
		$auditLog = $this->audit_log;

		$args = array(
			'search'   => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
			'action'   => isset( $_GET['filter_action'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_action'] ) ) : '',
			'severity' => isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '',
			'module'   => isset( $_GET['module'] ) ? sanitize_key( wp_unslash( $_GET['module'] ) ) : '',
			'paged'    => isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1,
			'per_page' => 20,
		);

		$rows        = $auditLog->query( $args );
		$total       = $auditLog->count( $args );
		$total_pages = (int) ceil( $total / $args['per_page'] );

		// Effective retention (admin General-tab setting, plus any pro override) —
		// same value the daily cleanup uses, so the note always matches reality.
		$retention_days = (int) apply_filters( 'qevix_shield_log_retention_days', 7 );

		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/logs.php';
	}
}
