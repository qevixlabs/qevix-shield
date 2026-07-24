<?php
/**
 * Orchestrator: instantiates every module and wires its hooks through
 * the loader. This is the only file that knows how modules depend on
 * each other.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/class-qevix-shield-util.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/class-qevix-shield-crypto.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/class-qevix-shield-settings.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/class-qevix-shield-hide-login.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/class-qevix-shield-dashboard.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/class-qevix-shield-menu.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/class-qevix-shield-teasers.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-login-protect.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-rate-limit.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-password-policy.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-xmlrpc.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-sessions.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-totp.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-login-context.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-2fa.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/auth/class-qevix-shield-recaptcha.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/security/class-qevix-shield-file-security.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/security/class-qevix-shield-hardening.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/security/class-qevix-shield-firewall.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/malware/class-qevix-shield-malware-scanner.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/logs/class-qevix-shield-audit-log.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/notifications/class-qevix-shield-alerts.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/api/class-qevix-shield-pro-bridge.php';

class QevixShield {

	/** @var QevixShield_Loader */
	private $loader;

	public function __construct() {
		$this->loader = new QevixShield_Loader();

		$settings      = new QevixShield_Settings();
		$auditLog      = new QevixShield_Audit_Log();

		// These two run NOW — at plugin-include time, not on a hook — because
		// their whole value is acting before the rest of WordPress loads:
		// the firewall must reject attack requests before other plugins (or
		// pluggable.php) execute, and error display must be off before any
		// later code can emit a notice. This is the one sanctioned exception
		// to "the loader wires everything".
		$firewall  = new QevixShield_Firewall( $settings );
		$hardening = new QevixShield_Hardening( $settings );
		// Safe Mode (QEVIX_SHIELD_SAFE_MODE in wp-config.php) is the master
		// off-switch: an admin who has locked themselves out — forgotten hidden
		// login slug, misconfigured 2FA/reCAPTCHA, self-inflicted IP ban — adds
		// one line to wp-config and every enforcement path (here and in the pro
		// plugin) goes inert WITHOUT touching a single saved option. Settings
		// stay exactly as checked; only enforcement is suspended. Even these
		// two include-time actions are skipped so a bad firewall rule or error-
		// display suppression can't get in the way of recovery.
		// The firewall + error-display suppression are part of the File Security
		// tab, so they honour its master switch too (as well as Safe Mode).
		if ( ! self::is_safe_mode() && $settings->get( 'file_security_enabled', false ) ) {
			$firewall->run_early_check();
			$hardening->suppress_error_display();
		}

		$loginProtect = new QevixShield_Login_Protect( $settings );
		$rateLimit    = new QevixShield_Rate_Limit( $settings, $loginProtect );
		$password     = new QevixShield_Password_Policy( $settings );
		$xmlrpc       = new QevixShield_XMLRPC( $settings );
		$alerts       = new QevixShield_Alerts( $settings );
		$hideLogin    = new QevixShield_Hide_Login( $settings );
		$dashboard    = new QevixShield_Dashboard( $auditLog );
		$sessions     = new QevixShield_Sessions();
		$scanner      = new QevixShield_Malware_Scanner( $settings );
		$twofa        = new QevixShield_TwoFA( $settings );
		$recaptcha    = new QevixShield_Recaptcha( $settings );
		$fileSecurity = new QevixShield_File_Security( $settings );
		$menu         = new QevixShield_Menu( $dashboard, $settings, $auditLog, $sessions, $scanner, $fileSecurity );
		$teasers      = new QevixShield_Teasers();
		$proBridge    = new QevixShield_Pro_Bridge();

		// Always wired — none of these can lock anyone out, and passive audit
		// logging is what feeds the diagnostic report a stuck customer sends to
		// support. The admin menu (incl. the pro License tab) must stay
		// reachable in Safe Mode so recovery is possible from the dashboard.
		$this->define_admin_hooks( $menu, $settings, $auditLog, $dashboard );
		$this->define_teaser_hooks( $teasers );
		$this->define_pro_bridge_hooks( $proBridge );
		$this->define_malware_hooks( $scanner );
		$this->define_session_hooks( $sessions );
		$this->define_audit_log_hooks( $auditLog );
		$this->define_alert_hooks( $alerts );
		// 2FA & reCAPTCHA UI/registration + per-user management + admin reset —
		// always wired (none of it can lock anyone out; the enrollment tab and a
		// user's own "Disable 2FA" button must stay reachable even in Safe Mode).
		$this->define_twofa_admin_hooks( $twofa );
		$this->define_recaptcha_admin_hooks( $recaptcha );

		// Enforcement hooks — the only paths that can 404 a request, block a
		// login, rewrite .htaccess, or gate an endpoint. Safe Mode skips wiring
		// them entirely (cleaner than a per-callback bail: the hooks simply
		// never attach, so there is no ordering or early-return to get wrong).
		// Each module also honours its tab's own master switch (a saved setting,
		// unlike the wp-config Safe Mode constant): while a tab's master is off,
		// its enforcement hooks simply never attach, so the sub-settings can be
		// drafted and switched on later without any of them acting in the
		// meantime. Password Security gates itself inside validate() instead (it
		// must stay wired to know a password was submitted), so it's always here.
		if ( ! self::is_safe_mode() ) {
			// File Security stays wired even while its master is off: handle_request
			// self-gates (no enforcement), and sync_server_rules must remain hooked
			// so a save with the master off can RETRACT the managed .htaccess rules
			// rather than leave the web server enforcing what PHP no longer does.
			// Hardening + the firewall have no persistent server rules, so they are
			// simply not wired while the master is off.
			$this->define_file_security_hooks( $fileSecurity );
			if ( $settings->get( 'file_security_enabled', false ) ) {
				$this->define_hardening_hooks( $hardening );
			}
			$this->define_hide_login_hooks( $hideLogin );
			if ( $settings->get( 'login_protection_enabled', false ) ) {
				$this->define_login_protect_hooks( $loginProtect );
				$this->define_rate_limit_hooks( $rateLimit );
			}
			$this->define_password_policy_hooks( $password );
			if ( $settings->get( 'xmlrpc_enabled', false ) ) {
				$this->define_xmlrpc_hooks( $xmlrpc );
			}
			// 2FA is opt-in per user, so its enforcement is always wired (outside
			// Safe Mode): the login challenge fires only for users who actually
			// enrolled, and forced enrollment self-gates on the twofa_enabled
			// master + role. reCAPTCHA is site-wide, so it stays gated on its own
			// master switch, mirroring the other tabs. Safe Mode skips this whole
			// block, so a self-inflicted 2FA/reCAPTCHA lockout is recoverable via
			// wp-config without touching a saved setting.
			$this->define_twofa_enforcement_hooks( $twofa );
			if ( $settings->get( 'recaptcha_enabled', false ) ) {
				$this->define_recaptcha_enforcement_hooks( $recaptcha );
			}
		}
	}

	/**
	 * Master kill-switch. `define( 'QEVIX_SHIELD_SAFE_MODE', true );` in
	 * wp-config.php suspends every Qevix Shield + Qevix Shield Pro enforcement path
	 * without altering a single saved setting — the documented, no-shell way
	 * back in for an admin who has locked themselves out. Read at include time
	 * (the constant is defined before plugins load), so it decides which hooks
	 * ever attach; the pro plugin reads this same method, so one line covers
	 * both. NOTE: server-level rules already written to .htaccess/nginx are
	 * enforced by the web server, not PHP, so Safe Mode cannot retract them —
	 * a login/2FA/reCAPTCHA/rate-limit/IP-ban lockout is covered; a
	 * File-Security .htaccess lockout still needs the file edited by hand.
	 */
	public static function is_safe_mode() {
		return defined( 'QEVIX_SHIELD_SAFE_MODE' ) && QEVIX_SHIELD_SAFE_MODE;
	}

	private function define_admin_hooks( QevixShield_Menu $menu, QevixShield_Settings $settings, QevixShield_Audit_Log $auditLog, QevixShield_Dashboard $dashboard ) {
		// Grant the Qevix Shield capability to admins + configured roles.
		$this->loader->add_filter( 'user_has_cap', $settings, 'grant_access_cap', 10, 4 );
		// Registered unconditionally (not just in wp-admin) so it also applies
		// during the WP-cron cleanup run.
		$this->loader->add_filter( 'qevix_shield_log_retention_days', $settings, 'filter_log_retention_days' );
		$this->loader->add_filter( 'qevix_shield_admin_pages', $menu, 'register_admin_pages' );
		$this->loader->add_filter( 'qevix_shield_settings_tabs', $menu, 'register_settings_tabs' );
		$this->loader->add_action( 'admin_menu', $menu, 'add_menu' );
		$this->loader->add_action( 'admin_enqueue_scripts', $menu, 'enqueue_assets' );
		// Loud, non-dismissible warning whenever Safe Mode is suspending
		// protection, so an admin never forgets the site is unguarded.
		$this->loader->add_action( 'admin_notices', $menu, 'render_safe_mode_notice' );
		// Security-summary widget on the main WordPress Dashboard.
		$this->loader->add_action( 'wp_dashboard_setup', $dashboard, 'register_dashboard_widget' );
		$this->loader->add_action( 'admin_enqueue_scripts', $dashboard, 'enqueue_dashboard_assets' );
		$this->loader->add_action( 'admin_post_qevix_shield_save_settings', $settings, 'handle_save' );
		$this->loader->add_action( 'admin_post_qevix_shield_export_csv', $auditLog, 'handle_csv_export' );
		$this->loader->add_action( 'wp_ajax_qevix_shield_poll_logs', $auditLog, 'ajax_poll' );
	}

	/**
	 * Locked pro teasers register at priority 20 — after the free plugin's own
	 * tabs/pages (priority 10) and, crucially, they carry the 'placeholder'
	 * flag so the menu builder's dedupe drops them the moment the real pro
	 * plugin registers the same slugs.
	 */
	private function define_teaser_hooks( QevixShield_Teasers $teasers ) {
		$this->loader->add_filter( 'qevix_shield_admin_pages', $teasers, 'register_admin_pages', 20 );
		$this->loader->add_filter( 'qevix_shield_settings_tabs', $teasers, 'register_settings_tabs', 20 );
	}

	private function define_pro_bridge_hooks( QevixShield_Pro_Bridge $proBridge ) {
		$this->loader->add_filter( 'qevix_shield_is_pro_active', $proBridge, 'is_pro_active' );
	}

	/**
	 * Block Sensitive Files: priority 0 so a sensitive-file probe is 404'd
	 * before the hide-login handler (priority 1) gets a chance to interpret
	 * the same request.
	 */
	private function define_file_security_hooks( QevixShield_File_Security $fileSecurity ) {
		$this->loader->add_action( 'init', $fileSecurity, 'handle_request', 0 );
		// Fired after a File Security save to rewrite the managed .htaccess rules (Apache only).
		$this->loader->add_action( 'qevix_shield_sync_server_rules', $fileSecurity, 'sync_server_rules' );
	}

	/**
	 * Information-disclosure hardening (version/REST/enumeration/headers/
	 * errors). Error-display suppression and the firewall already ran at
	 * include time in the constructor — see the comment there.
	 */
	private function define_hardening_hooks( QevixShield_Hardening $hardening ) {
		$this->loader->add_action( 'init', $hardening, 'apply_hardening', 1 );
		// Priority 2: after apply_hardening, still before canonical redirects.
		$this->loader->add_action( 'init', $hardening, 'block_author_enumeration', 2 );
		$this->loader->add_filter( 'script_loader_src', $hardening, 'strip_version_query', 9999 );
		$this->loader->add_filter( 'style_loader_src', $hardening, 'strip_version_query', 9999 );
		$this->loader->add_filter( 'rest_authentication_errors', $hardening, 'require_rest_auth', 99 );
		$this->loader->add_filter( 'rest_endpoints', $hardening, 'filter_rest_endpoints' );
		$this->loader->add_filter( 'wp_sitemaps_add_provider', $hardening, 'filter_sitemap_provider', 10, 2 );
		$this->loader->add_filter( 'wp_headers', $hardening, 'filter_wp_headers' );
	}

	private function define_hide_login_hooks( QevixShield_Hide_Login $hideLogin ) {
		$this->loader->add_action( 'init', $hideLogin, 'handle_request', 1 );
		$this->loader->add_filter( 'site_url', $hideLogin, 'filter_login_url', 10, 3 );
		$this->loader->add_filter( 'network_site_url', $hideLogin, 'filter_login_url', 10, 3 );
	}

	private function define_login_protect_hooks( QevixShield_Login_Protect $loginProtect ) {
		$this->loader->add_action( 'login_form', $loginProtect, 'render_honeypot_field' );
		$this->loader->add_filter( 'qevix_shield_ip_whitelisted', $loginProtect, 'filter_ip_whitelist', 10, 2 );
		// Priority 30: WP core's own `wp_authenticate_username_password` (priority 20)
		// ignores any WP_Error it's handed when credentials are valid and returns its
		// own fresh WP_User — so this must run AFTER core to actually override it.
		$this->loader->add_filter( 'authenticate', $loginProtect, 'check_honeypot', 30 );
	}

	private function define_rate_limit_hooks( QevixShield_Rate_Limit $rateLimit ) {
		// Same reasoning as the honeypot check above: must run after core's priority-20
		// authenticate callback so a locked-out IP is blocked even with a correct password.
		$this->loader->add_filter( 'authenticate', $rateLimit, 'check_lockout', 30 );
		$this->loader->add_action( 'wp_login_failed', $rateLimit, 'on_login_failed' );
		$this->loader->add_action( 'wp_login', $rateLimit, 'on_login_success' );
	}

	/** Enforces the password policy everywhere a password can be set: registration, profile/admin-create, and reset. */
	private function define_password_policy_hooks( QevixShield_Password_Policy $password ) {
		$this->loader->add_filter( 'registration_errors', $password, 'on_registration_errors', 10, 3 );
		$this->loader->add_action( 'user_profile_update_errors', $password, 'on_profile_update_errors', 10, 3 );
		$this->loader->add_action( 'validate_password_reset', $password, 'on_validate_password_reset', 10, 2 );
	}

	/** Logging runs on `init` (fires during xmlrpc.php too); enforcement hooks the server's own method/enabled/header filters. */
	private function define_xmlrpc_hooks( QevixShield_XMLRPC $xmlrpc ) {
		$this->loader->add_action( 'init', $xmlrpc, 'maybe_log_request', 5 );
		$this->loader->add_filter( 'xmlrpc_enabled', $xmlrpc, 'filter_enabled' );
		$this->loader->add_filter( 'xmlrpc_methods', $xmlrpc, 'filter_methods' );
		$this->loader->add_filter( 'wp_headers', $xmlrpc, 'filter_headers' );
	}

	private function define_malware_hooks( QevixShield_Malware_Scanner $scanner ) {
		$this->loader->add_action( 'admin_post_qevix_shield_run_scan', $scanner, 'handle_run_scan' );
	}

	/**
	 * Two-Factor Auth — tab/submenu registration, per-user enrollment
	 * management, and admin reset. None of this enforces anything, so it stays
	 * wired even in Safe Mode (a user must always be able to reach the tab and
	 * disable their own 2FA to recover). The enrollment QR script loads here too.
	 */
	private function define_twofa_admin_hooks( QevixShield_TwoFA $twofa ) {
		$this->loader->add_filter( 'qevix_shield_admin_pages', $twofa, 'register_admin_pages' );
		$this->loader->add_filter( 'qevix_shield_settings_tabs', $twofa, 'register_settings_tabs' );
		$this->loader->add_action( 'admin_enqueue_scripts', $twofa, 'enqueue_assets' );
		$this->loader->add_action( 'admin_post_qevix_shield_2fa_policy', $twofa, 'handle_policy_save' );
		$this->loader->add_action( 'admin_post_qevix_shield_2fa_enroll', $twofa, 'handle_enroll' );
		$this->loader->add_action( 'admin_post_qevix_shield_2fa_disable', $twofa, 'handle_disable' );
		$this->loader->add_action( 'admin_post_qevix_shield_2fa_recovery', $twofa, 'handle_regenerate_recovery' );
		$this->loader->add_action( 'edit_user_profile', $twofa, 'render_admin_reset_field' );
		$this->loader->add_action( 'edit_user_profile_update', $twofa, 'handle_admin_reset' );
	}

	/**
	 * Two-Factor Auth enforcement: the login challenge, forced enrollment for
	 * enforced roles, and the lost-password second-factor gate. Wired only while
	 * the twofa_enabled master switch is on and Safe Mode is off.
	 */
	private function define_twofa_enforcement_hooks( QevixShield_TwoFA $twofa ) {
		// Runs after every other authenticate check (WP core's at 20, free's
		// lockout/honeypot at 30) so the OTP screen only hides a wrong password.
		$this->loader->add_filter( 'authenticate', $twofa, 'intercept_authentication', 9999, 3 );
		$this->loader->add_action( 'login_form_qevix_shield_2fa', $twofa, 'handle_challenge' );
		$this->loader->add_filter( 'wp_login_errors', $twofa, 'filter_login_errors' );
		$this->loader->add_filter( 'login_redirect', $twofa, 'filter_login_redirect', 10, 3 );
		$this->loader->add_action( 'admin_init', $twofa, 'enforce_enrollment' );
		$this->loader->add_action( 'lostpassword_form', $twofa, 'render_lostpassword_field' );
		$this->loader->add_action( 'lostpassword_post', $twofa, 'verify_lostpassword', 20, 2 );
	}

	/** reCAPTCHA — tab/submenu registration + the settings save handler (always wired). */
	private function define_recaptcha_admin_hooks( QevixShield_Recaptcha $recaptcha ) {
		$this->loader->add_filter( 'qevix_shield_admin_pages', $recaptcha, 'register_admin_pages' );
		$this->loader->add_filter( 'qevix_shield_settings_tabs', $recaptcha, 'register_settings_tabs' );
		$this->loader->add_action( 'admin_post_qevix_shield_recaptcha_save', $recaptcha, 'handle_save' );
		// "Test keys" preflight — proves a key pair works before the master
		// switch can be turned on. Admin-only (capability checked inside).
		$this->loader->add_action( 'wp_ajax_qevix_shield_recaptcha_test', $recaptcha, 'ajax_test' );
	}

	/**
	 * reCAPTCHA enforcement: enqueue the API script, render the token field, and
	 * verify it on the login / registration / lost-password forms. Wired only
	 * while the recaptcha_enabled master switch is on and Safe Mode is off (the
	 * module still no-ops until both keys are set). WooCommerce/custom-form
	 * coverage is added by the pro plugin against this same instance.
	 */
	private function define_recaptcha_enforcement_hooks( QevixShield_Recaptcha $recaptcha ) {
		$this->loader->add_action( 'login_enqueue_scripts', $recaptcha, 'enqueue' );
		$this->loader->add_action( 'login_form', $recaptcha, 'render_field' );
		// Email sign-in verification fallback (pro-enabled): relays the emailed
		// token through the form + shows the arrival banner. Both self-gate on
		// the pro filter, so they are inert markup-free on free installs.
		$this->loader->add_action( 'login_form', $recaptcha, 'render_verification_field' );
		$this->loader->add_filter( 'login_message', $recaptcha, 'verification_login_message' );
		$this->loader->add_filter( 'authenticate', $recaptcha, 'verify', 25 );
		$this->loader->add_action( 'register_form', $recaptcha, 'render_register_field' );
		$this->loader->add_filter( 'registration_errors', $recaptcha, 'verify_registration', 25, 3 );
		$this->loader->add_action( 'lostpassword_form', $recaptcha, 'render_lostpassword_field' );
		$this->loader->add_action( 'lostpassword_post', $recaptcha, 'verify_lostpassword', 15, 2 );
	}

	private function define_session_hooks( QevixShield_Sessions $sessions ) {
		$this->loader->add_filter( 'attach_session_information', $sessions, 'attach_session_information', 10, 2 );
		$this->loader->add_action( 'init', $sessions, 'track_activity', 10 );
		// A password reset invalidates all of that user's sessions.
		$this->loader->add_action( 'after_password_reset', $sessions, 'force_logout_on_password_reset' );
		// Self-service: end all of my own sessions except the current one.
		$this->loader->add_action( 'admin_post_qevix_shield_logout_others', $sessions, 'handle_logout_others' );
	}

	private function define_audit_log_hooks( QevixShield_Audit_Log $auditLog ) {
		$this->loader->add_action( 'wp_login', $auditLog, 'on_login_success', 10, 2 );
		$this->loader->add_action( 'wp_login_failed', $auditLog, 'on_login_failed' );
		$this->loader->add_action( 'wp_logout', $auditLog, 'on_logout' );
		$this->loader->add_action( 'password_reset', $auditLog, 'on_password_reset' );
		$this->loader->add_action( 'user_register', $auditLog, 'on_user_register' );
		$this->loader->add_action( 'deleted_user', $auditLog, 'on_user_deleted' );
		$this->loader->add_action( 'set_user_role', $auditLog, 'on_user_role_changed', 10, 3 );
		// Self-monitoring: Qevix Shield's own free/pro plugin being enabled,
		// disabled, updated, or reconfigured.
		$this->loader->add_action( 'activated_plugin', $auditLog, 'on_plugin_activated', 10, 2 );
		$this->loader->add_action( 'deactivated_plugin', $auditLog, 'on_plugin_deactivated', 10, 2 );
		$this->loader->add_action( 'upgrader_process_complete', $auditLog, 'on_plugin_updated', 10, 2 );
		$this->loader->add_action( 'update_option_qevix_shield_settings', $auditLog, 'on_settings_changed', 10, 3 );
		$this->loader->add_action( 'update_option_qevix_shield_pro_settings', $auditLog, 'on_settings_changed', 10, 3 );
		$this->loader->add_action( 'qevix_shield_daily_log_cleanup', $auditLog, 'cleanup_old_logs' );
	}

	private function define_alert_hooks( QevixShield_Alerts $alerts ) {
		// maybe_notify only gates + schedules; the actual wp_mail() runs off the
		// audited request in the deferred qevix_shield_send_alert cron event.
		$this->loader->add_action( 'qevix_shield_after_log', $alerts, 'maybe_notify' );
		$this->loader->add_action( 'qevix_shield_send_alert', $alerts, 'dispatch_alert' );
	}

	public function run() {
		$this->loader->run();
	}
}
