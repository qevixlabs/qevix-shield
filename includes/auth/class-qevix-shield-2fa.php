<?php
/**
 * Two-factor authentication (free tier), built on the shared QevixShield_TOTP
 * engine.
 *
 *  - Enrollment: QR (rendered client-side from the otpauth URI) + manual key,
 *    confirmed by entering a live code, then one-time recovery codes.
 *  - Login challenge (username-first order): the login form stays stock
 *    WordPress (username + password only — no extra field). Screen 1 only
 *    resolves the USERNAME: nonexistent → core's error; exists + enrolled →
 *    the OTP screen renders with the password deliberately unchecked (identical
 *    response for right and wrong passwords, carried forward encrypted); exists
 *    + not enrolled → normal password login. Only after the OTP verifies does
 *    the full username+password check run (wp_authenticate), and cookies/session
 *    are generated exclusively on its success. Wrong OTPs fire wp_login_failed
 *    so the free rate limiter counts them.
 *  - Role enforcement: a user in an enforced role who hasn't enrolled logs in
 *    with password only, then their FIRST screen is a standalone full-page 2FA
 *    setup (rendered on admin_init, before any admin chrome) until they enrol.
 *    FREE enforces the Administrator role only; the pro plugin unlocks per-role
 *    selection via the qevix_shield_2fa_enforced_roles filter.
 *  - Recovery codes + admin reset are free (a locked-out user must have a way
 *    back in — the no-lockout rule).
 *
 * Pro extension seams (all no-ops without the pro plugin):
 *  - qevix_shield_2fa_enforced_roles   (filter) — pro returns the full role set.
 *  - qevix_shield_2fa_trusted_devices  (filter) — pro enables the trust checkbox.
 *  - qevix_shield_2fa_device_trusted   (filter) — pro skips the challenge on a trusted device.
 *  - qevix_shield_2fa_trust_device     (action) — pro persists a trusted device.
 *  - qevix_shield_2fa_email_fallback    (filter) — pro enables the emailed-code path.
 *  - qevix_shield_2fa_send_code         (action) — pro emails a one-time code.
 *  - qevix_shield_2fa_alt_verify        (filter) — pro verifies an emailed code.
 *  - qevix_shield_2fa_reset_user        (action) — pro clears its own per-user meta.
 *  - qevix_shield_twofa_pro_values / qevix_shield_twofa_save_pro — advanced policy fields.
 *
 * Enforcement is gated on the twofa_enabled master switch and suspended by
 * Safe Mode / the disable constants, so a misconfiguration can never lock an
 * admin out with no way back in.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_TwoFA {

	const META_SECRET   = 'qevix_shield_2fa_secret';    // encrypted TOTP secret.
	const META_ENABLED  = 'qevix_shield_2fa_enabled';   // '1' once confirmed.
	const META_RECOVERY = 'qevix_shield_2fa_recovery';  // array of password_hash()es.
	const META_NONCE    = 'qevix_shield_2fa_login_nonce';

	/** @var QevixShield_Settings */
	private $settings;

	/**
	 * Reentrancy guard: handle_challenge() runs the REAL credential check via
	 * wp_authenticate() after the OTP verifies, which re-fires the authenticate
	 * filter — this flag stops intercept_authentication() from rendering a
	 * second challenge inside that call.
	 *
	 * @var bool
	 */
	private $completing_challenge = false;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	/* ============================ helpers ============================ */

	/**
	 * Emergency kill-switches (any one of them suspends enforcement):
	 *  - QEVIX_SHIELD_SAFE_MODE / QevixShield::is_safe_mode() — the master hatch.
	 *  - QEVIX_SHIELD_DISABLE_2FA — the 2FA-specific hatch.
	 *  - QEVIX_SHIELD_PRO_DISABLE_2FA — honored for back-compat with pro installs.
	 * Enrolled secrets are preserved and resume the moment the line is removed.
	 * Not filterable — a filter here would bypass the protection, not just the
	 * escape hatch; editing wp-config already implies full server access.
	 */
	public static function is_bypassed() {
		if ( class_exists( 'QevixShield' ) && QevixShield::is_safe_mode() ) {
			return true;
		}
		if ( defined( 'QEVIX_SHIELD_DISABLE_2FA' ) && QEVIX_SHIELD_DISABLE_2FA ) {
			return true;
		}
		return defined( 'QEVIX_SHIELD_PRO_DISABLE_2FA' ) && QEVIX_SHIELD_PRO_DISABLE_2FA;
	}

	/**
	 * Whether 2FA enforcement runs at all — the login challenge for users who
	 * have enrolled. Two-factor is opt-in and setup is ALWAYS available, so a
	 * user who set up 2FA is challenged whether or not the site-wide "Enable
	 * 2FA" switch is on; only the emergency bypasses (Safe Mode / disable
	 * constants) suspend it. The master switch governs forced enrollment
	 * (forcing()), not whether an enrolled user is challenged.
	 */
	private function enforced() {
		return ! self::is_bypassed();
	}

	/**
	 * Whether users in an enforced role are FORCED to enrol — the "Enable 2FA"
	 * master switch. Also gates the lost-password 2FA field so it only appears
	 * once 2FA is switched on site-wide (individual opt-in still challenges
	 * logins via enforced()). Off by default (neutral activation).
	 */
	private function forcing() {
		return $this->enforced() && (bool) $this->settings->get( 'twofa_enabled', false );
	}

	public function user_has_2fa( $userId ) {
		return '1' === get_user_meta( $userId, self::META_ENABLED, true );
	}

	private function get_secret( $userId ) {
		$stored = get_user_meta( $userId, self::META_SECRET, true );
		if ( '' === $stored ) {
			return '';
		}
		$plain = QevixShield_Crypto::decrypt( $stored );
		return false === $plain ? '' : $plain;
	}

	/**
	 * Which roles must enrol. Owned by this plugin's own setting and selectable
	 * on every tier — Administrator is only the default, not a ceiling. The
	 * filter stays a public extension point, not a licence gate.
	 */
	private function enforced_roles() {
		$stored = (array) $this->settings->get( 'twofa_enforced_roles', array( 'administrator' ) );
		if ( empty( $stored ) ) {
			$stored = array( 'administrator' );
		}
		$roles = (array) apply_filters( 'qevix_shield_2fa_enforced_roles', $stored );
		return array_values( array_filter( array_map( 'strval', $roles ) ) );
	}

	private function role_is_enforced( $user ) {
		$roles = $this->enforced_roles();
		if ( empty( $roles ) ) {
			return false;
		}
		return (bool) array_intersect( (array) $user->roles, $roles );
	}

	/** Pro enables the emailed-code fallback; free has none (recovery codes instead). */
	private function email_fallback_enabled() {
		return (bool) apply_filters( 'qevix_shield_2fa_email_fallback', false );
	}

	/** Pro enables trusted devices (the "trust this device" checkbox + skip). */
	private function trusted_devices_enabled() {
		return (bool) apply_filters( 'qevix_shield_2fa_trusted_devices', false );
	}

	/* ========================= enrollment =========================== */

	/** Adds a Two-Factor Auth tab to the shared Settings page. */
	public function register_settings_tabs( $tabs ) {
		$tabs[] = array(
			'slug'       => 'twofa',
			'label'      => __( 'Two-Factor Auth', 'qevix-shield' ),
			'render'     => array( $this, 'render_section' ),
			'capability' => 'read', // enrollment is available to every user.
			'position'   => 16,
		);
		return $tabs;
	}

	public function register_admin_pages( $pages ) {
		$pages[] = array(
			'slug'       => 'qevix-shield-2fa',
			'page_title' => __( 'Qevix Shield Two-Factor Authentication', 'qevix-shield' ),
			'menu_title' => __( 'Two-Factor Auth', 'qevix-shield' ),
			'capability' => 'read',
			'callback'   => array( $this, 'render_page' ),
			'tab'        => 'twofa',
			'position'   => 16,
		);
		return $pages;
	}

	public function enqueue_assets( $hook ) {
		// The enrollment QR renders on the standalone 2FA page AND inside the
		// shared Settings page (Two-Factor Auth tab), so load on any Qevix Shield
		// admin screen.
		if ( false === strpos( (string) $hook, 'qevix-shield' ) ) {
			return;
		}
		wp_enqueue_script( 'qevix-shield-qrcode', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/qrcode.js', array(), '1.0.0', true );
		// The QR renderer reads window.QevixShield2FAQR.otpauth, which the 2FA
		// settings view localizes when there is a pending enrolment.
		wp_enqueue_script( 'qevix-shield-twofa-qr', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/twofa-qr.js', array( 'qevix-shield-qrcode' ), QEVIX_SHIELD_VERSION, true );
	}

	/** Submenu page: opens the shared tabbed Settings view on the 2FA tab. */
	public function render_page() {
		QevixShield_Menu::render_tabbed_settings( 'twofa' );
	}

	/** The policy + enrollment UI — shared by the standalone page and Settings tab. */
	public function render_section() {
		$userId     = get_current_user_id();
		$masterOn   = (bool) $this->settings->get( 'twofa_enabled', false );
		$enabled    = $this->user_has_2fa( $userId );
		$isPro      = (bool) apply_filters( 'qevix_shield_is_pro_active', false );
		$xmlrpcMode = (string) $this->settings->get( 'twofa_xmlrpc_mode', 'allow' );

		// A pending (unconfirmed) secret lives in a transient during enrollment
		// so an abandoned enrollment never leaves a half-set secret on the user.
		// Setup is always available (opt-in, no site-wide-switch restriction), so
		// generate a pending secret for any not-yet-enrolled user.
		$pendingSecret = get_transient( 'qevix_shield_2fa_pending_' . $userId );

		if ( ! $enabled && ! $pendingSecret ) {
			$pendingSecret = QevixShield_TOTP::generate_secret();
			set_transient( 'qevix_shield_2fa_pending_' . $userId, $pendingSecret, 15 * MINUTE_IN_SECONDS );
		}

		$issuer      = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$account     = wp_get_current_user()->user_login;
		$otpauthUri  = $pendingSecret ? QevixShield_TOTP::provisioning_uri( $pendingSecret, $account, $issuer ) : '';
		$recoveryNew = get_transient( 'qevix_shield_2fa_recovery_show_' . $userId );
		delete_transient( 'qevix_shield_2fa_recovery_show_' . $userId );

		// The view reads the enforced-role selection straight from settings (it
		// is a free-tier setting now), so hand it the settings object like every
		// other tab's view gets.
		$settings = $this->settings;

		// Advanced (pro) policy values the shared form renders; pro overlays its
		// saved values, free ships the neutral defaults.
		$proValues = (array) apply_filters(
			'qevix_shield_twofa_pro_values',
			array(
				'twofa_trusted_days'   => 30,
				'twofa_email_fallback' => false,
			)
		);

		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-twofa.php';
	}

	/** Confirm enrollment: user typed a code proving their app has the secret. */
	public function handle_enroll() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_2fa_enroll' );

		$userId = get_current_user_id();
		$secret = get_transient( 'qevix_shield_2fa_pending_' . $userId );
		// Prefixed field name (was the generic `code`, renamed 2026-07-18 —
		// generic ids/names risk colliding with other plugins' admin scripts).
		$code   = isset( $_POST['qevix_shield_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['qevix_shield_2fa_code'] ) ) : '';

		// Setup is opt-in and unrestricted — enrollment does not require the
		// site-wide master switch; a user who confirms a valid code is enrolled.
		if ( $secret && QevixShield_TOTP::verify( $secret, $code ) ) {
			update_user_meta( $userId, self::META_SECRET, QevixShield_Crypto::encrypt( $secret ) );
			update_user_meta( $userId, self::META_ENABLED, '1' );
			delete_transient( 'qevix_shield_2fa_pending_' . $userId );

			$codes = $this->generate_recovery_codes( $userId );
			set_transient( 'qevix_shield_2fa_recovery_show_' . $userId, $codes, 5 * MINUTE_IN_SECONDS );

			QevixShield_Audit_Log::log( array( 'action' => '2fa_enabled', 'severity' => 'info', 'module' => 'auth', 'status' => 'success', 'user_id' => $userId ) );

			wp_safe_redirect( admin_url( 'admin.php?page=qevix-shield-2fa&enrolled=1' ) );
			exit;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=qevix-shield-2fa&enroll_error=1' ) );
		exit;
	}

	/** Admin-only: enable 2FA site-wide. Advanced fields are persisted by pro. */
	public function handle_policy_save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_2fa_policy' );

		// Enforced roles are a free-tier setting: whatever the admin ticked is
		// what gets enforced, validated against the roles that actually exist on
		// this site. Administrator is the floor — an empty selection falls back
		// to it rather than quietly enforcing 2FA on nobody while the master
		// switch reads "on".
		$allRoles = array_keys( (array) wp_roles()->get_names() );
		$postedRoles = isset( $_POST['twofa_enforced_roles'] )
			? array_map( 'sanitize_key', (array) wp_unslash( $_POST['twofa_enforced_roles'] ) )
			: array();
		$roles = array_values( array_intersect( $postedRoles, $allRoles ) );
		if ( empty( $roles ) ) {
			$roles = array( 'administrator' );
		}

		$xmlrpcMode = isset( $_POST['twofa_xmlrpc_mode'] ) ? sanitize_key( wp_unslash( $_POST['twofa_xmlrpc_mode'] ) ) : 'allow';
		if ( ! in_array( $xmlrpcMode, array( 'allow', 'code', 'block' ), true ) ) {
			$xmlrpcMode = 'allow';
		}
		$this->settings->update(
			array(
				'twofa_enabled'        => ! empty( $_POST['twofa_enabled'] ),
				'twofa_enforced_roles' => $roles,
				'twofa_xmlrpc_mode'    => $xmlrpcMode,
			)
		);

		/**
		 * Persist the advanced policy fields (full role set, trusted-device
		 * days, emailed-code fallback). Pro's listener self-gates on is_valid()
		 * + manage_options.
		 */
		do_action( 'qevix_shield_twofa_save_pro' );

		wp_safe_redirect( admin_url( 'admin.php?page=qevix-shield-2fa&policy_saved=1' ) );
		exit;
	}

	public function handle_disable() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_2fa_disable' );
		$this->reset_user( get_current_user_id() );
		wp_safe_redirect( admin_url( 'admin.php?page=qevix-shield-2fa&disabled=1' ) );
		exit;
	}

	public function handle_regenerate_recovery() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_2fa_recovery' );
		$userId = get_current_user_id();
		$codes  = $this->generate_recovery_codes( $userId );
		set_transient( 'qevix_shield_2fa_recovery_show_' . $userId, $codes, 5 * MINUTE_IN_SECONDS );
		wp_safe_redirect( admin_url( 'admin.php?page=qevix-shield-2fa&recovery=1' ) );
		exit;
	}

	private function generate_recovery_codes( $userId, $count = 10 ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$code     = strtoupper( bin2hex( random_bytes( 4 ) ) ); // 8 hex chars.
			$code     = substr( $code, 0, 4 ) . '-' . substr( $code, 4 );
			$plain[]  = $code;
			$hashed[] = password_hash( $code, PASSWORD_DEFAULT );
		}
		update_user_meta( $userId, self::META_RECOVERY, $hashed );
		return $plain;
	}

	/* ===================== per-role enforcement ===================== */

	private function needs_forced_enrollment( $user ) {
		return $this->forcing()
			&& $user instanceof WP_User
			&& $this->role_is_enforced( $user )
			&& ! $this->user_has_2fa( $user->ID );
	}

	/**
	 * Hooked on login_redirect: an enforced-role user without 2FA always lands
	 * in wp-admin after login, so their first screen is the forced setup page
	 * (rendered by enforce_enrollment) regardless of any redirect_to.
	 */
	public function filter_login_redirect( $redirectTo, $requested, $user ) {
		if ( $this->needs_forced_enrollment( $user ) ) {
			return admin_url();
		}
		return $redirectTo;
	}

	/**
	 * Hooked on admin_init: an enforced-role user without 2FA gets a single
	 * standalone setup screen on EVERY wp-admin request — no admin page or menu
	 * is ever served — until they enrol. Only the enrollment confirmation POST
	 * (admin-post.php) and AJAX are let through.
	 */
	public function enforce_enrollment() {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $this->needs_forced_enrollment( $user ) ) {
			return;
		}
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		global $pagenow;
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( 'admin-post.php' === $pagenow && 'qevix_shield_2fa_enroll' === $action ) {
			return; // Let the enrollment confirmation itself through.
		}

		$this->render_forced_enrollment( $user );
		exit;
	}

	/**
	 * The standalone forced-setup page: a complete minimal HTML document (QR +
	 * manual key + confirm form + logout link). Rendered on admin_init, before
	 * any admin chrome, so nothing of wp-admin leaks out.
	 */
	private function render_forced_enrollment( $user ) {
		$pendingSecret = get_transient( 'qevix_shield_2fa_pending_' . $user->ID );
		if ( ! $pendingSecret ) {
			$pendingSecret = QevixShield_TOTP::generate_secret();
			set_transient( 'qevix_shield_2fa_pending_' . $user->ID, $pendingSecret, 15 * MINUTE_IN_SECONDS );
		}

		$issuer      = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$otpauthUri  = QevixShield_TOTP::provisioning_uri( $pendingSecret, $user->user_login, $issuer );
		$enrollError = isset( $_GET['enroll_error'] );

		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/twofa-setup-required.php';
	}

	/* ======================= login challenge ======================== */

	/**
	 * Hooked on lostpassword_form: 2FA-enrolled accounts must supply a valid
	 * code before a reset email is sent (enforced in verify_lostpassword).
	 */
	public function render_lostpassword_field() {
		if ( ! $this->forcing() ) {
			return;
		}
		?>
		<p>
			<label for="qevix_shield_2fa_lost_code"><?php esc_html_e( 'Authentication Code (2FA)', 'qevix-shield' ); ?></label>
			<input type="text" name="qevix_shield_2fa_lost_code" id="qevix_shield_2fa_lost_code" class="input" value="" size="20"
				inputmode="numeric" autocomplete="one-time-code" />
		</p>
		<p style="font-size:12px;color:#646970;margin:-8px 0 12px;"><?php esc_html_e( 'Required if two-factor authentication is enabled on your account; leave blank otherwise.', 'qevix-shield' ); ?></p>
		<?php if ( $this->email_fallback_enabled() ) : ?>
			<p style="margin:0 0 12px;">
				<button type="submit" name="qevix_shield_2fa_email_send" value="1" class="button-link" style="cursor:pointer;background:none;border:none;padding:0;color:#2271b1;text-decoration:underline;font-size:12px;">
					<?php esc_html_e( 'Lost your device? Email me a code instead', 'qevix-shield' ); ?>
				</button>
			</p>
		<?php endif; ?>
		<?php
	}

	/**
	 * Hooked on lostpassword_post. If the target account has 2FA enrolled, a
	 * valid TOTP or recovery code is required before the reset email is sent.
	 * Programmatic retrieve_password() calls (no form POST) and non-enrolled
	 * accounts are left alone.
	 *
	 * Anti-enumeration: nothing in the on-screen response may reveal whether an
	 * account has 2FA enabled to someone who only knows the username. A
	 * missing/invalid code therefore does NOT show an error — the request looks
	 * exactly like a successful one (core's usual "check your email"
	 * confirmation), but the reset email is suppressed and the account owner is
	 * emailed an explanation instead.
	 */
	public function verify_lostpassword( $errors, $userData = null ) {
		if ( ! $this->forcing() || ! is_wp_error( $errors ) ) {
			return;
		}
		// A gate earlier on this same hook (reCAPTCHA runs at priority 15, before
		// our 20) already rejected this submission — don't fire our email
		// side-effects for a request that won't be honored.
		if ( $errors->has_errors() ) {
			return;
		}
		if ( empty( $_POST ) || ! isset( $_POST['user_login'] ) ) {
			return;
		}

		$emailFallback = $this->email_fallback_enabled();

		// The "Lost your device?" button aborts this attempt and re-shows the
		// form (data 'message' renders as an info notice, not an error).
		// Identical response whether or not the account is enrolled.
		if ( $emailFallback && ! empty( $_POST['qevix_shield_2fa_email_send'] ) ) {
			if ( $userData instanceof WP_User && $this->user_has_2fa( $userData->ID ) ) {
				do_action( 'qevix_shield_2fa_send_code', $userData );
			}
			$errors->add( 'qevix_shield_2fa_email_sent', __( 'If this account has two-factor authentication enabled, a one-time code has been emailed to it. Enter it in the Authentication Code field below and submit again.', 'qevix-shield' ), 'message' );
			return;
		}

		if ( ! ( $userData instanceof WP_User ) || ! $this->user_has_2fa( $userData->ID ) ) {
			return;
		}

		$code   = isset( $_POST['qevix_shield_2fa_lost_code'] ) ? sanitize_text_field( wp_unslash( $_POST['qevix_shield_2fa_lost_code'] ) ) : '';
		$secret = $this->get_secret( $userData->ID );
		$ok     = '' !== $code && (
			( '' !== $secret && QevixShield_TOTP::verify( $secret, $code ) )
			|| $this->consume_recovery_code( $userData->ID, $code )
			|| ( $emailFallback && (bool) apply_filters( 'qevix_shield_2fa_alt_verify', false, $userData->ID, $code ) )
		);

		if ( ! $ok ) {
			QevixShield_Audit_Log::log( array( 'action' => '2fa_failed', 'severity' => 'warning', 'module' => 'auth', 'status' => 'failed', 'user_id' => $userData->ID ) );
			// No visible error: suppress the reset email for this request and
			// tell the account owner (the only party allowed to know the account
			// has 2FA) what's needed, by email.
			add_filter( 'send_retrieve_password_email', '__return_false' );
			add_filter( 'woocommerce_email_enabled_customer_reset_password', '__return_false' );
			$this->send_reset_blocked_email( $userData, $emailFallback );
		}
	}

	/**
	 * Sent to the account owner when a password-reset request was silently
	 * blocked because it lacked a valid second-factor code.
	 */
	private function send_reset_blocked_email( $user, $emailFallback ) {
		/* translators: %s site name */
		$subject = sprintf( __( '[%s] Password reset requires your authentication code', 'qevix-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );

		$explain  = __( 'A password reset was requested for your account, but it was not processed: your account is protected by two-factor authentication and the request did not include a valid authentication code.', 'qevix-shield' );
		$howto    = __( 'To reset your password, use the lost-password form again and enter the 6-digit code from your authenticator app (or a recovery code) in the Authentication Code field.', 'qevix-shield' );
		$fallback = __( 'Lost your device? Use the "Email me a code instead" button on that form to receive a one-time code at this address.', 'qevix-shield' );
		$ignore   = __( 'If you did not request a password reset, you can safely ignore this email.', 'qevix-shield' );

		$plaintext = $explain . "\n\n" . $howto . ( $emailFallback ? "\n\n" . $fallback : '' ) . "\n\n" . $ignore;

		$p     = static function ( $text, $muted = false ) {
			return '<p style="margin:0 0 14px;font-size:14px;line-height:1.6;color:' . ( $muted ? '#646970' : '#3c434a' ) . ';">' . esc_html( $text ) . '</p>';
		};
		$inner = $p( $explain ) . $p( $howto ) . ( $emailFallback ? $p( $fallback ) : '' ) . $p( $ignore, true );

		$html = QevixShield_Util::email_wrap( __( 'Password reset needs your code', 'qevix-shield' ), $inner );
		QevixShield_Util::send_html_mail( $user->user_email, $subject, $html, $plaintext );
	}

	/**
	 * Hooked VERY LATE on the authenticate filter (after every other check has
	 * had its say). The login form is stock WordPress (username + password
	 * only). Whether the OTP screen appears is decided by USERNAME LOOKUP ALONE
	 * — the password is NOT validated at this screen. The submitted password is
	 * carried forward encrypted at rest and the REAL credential check runs in
	 * handle_challenge() only after a valid OTP.
	 */
	public function intercept_authentication( $user, $username = '', $password = '' ) {
		if ( $this->completing_challenge ) {
			return $user;
		}
		if ( ! $this->enforced() || '' === (string) $username ) {
			return $user;
		}
		if ( ! QevixShield_Login_Context::is_interactive_login_post( $username, $password ) ) {
			// No challenge screen exists off the login form, so XML-RPC password
			// logins would sidestep 2FA entirely — apply the XML-RPC policy
			// instead (other non-interactive contexts stay untouched).
			return $this->apply_xmlrpc_policy( $user, $username, $password );
		}
		$wooLogin = $this->is_woo_login_post();

		// Resolve the account from the username alone (login name or email,
		// mirroring core's own resolution).
		$account = get_user_by( 'login', $username );
		if ( ! $account && is_email( $username ) ) {
			$account = get_user_by( 'email', $username );
		}
		if ( ! $account || ! $this->user_has_2fa( $account->ID ) ) {
			return $user;
		}
		if ( (bool) apply_filters( 'qevix_shield_2fa_device_trusted', false, $account->ID ) ) {
			return $user;
		}

		// Only a wrong-password result is hidden behind the OTP screen; every
		// other error (lockout, honeypot, reCAPTCHA, empty password) shows.
		if ( is_wp_error( $user ) && ! in_array( 'incorrect_password', $user->get_error_codes(), true ) ) {
			return $user;
		}

		$pwdEnc = '' !== (string) $password ? QevixShield_Crypto::encrypt( (string) $password ) : '';
		$nonce  = $this->issue_login_nonce( $account->ID, $pwdEnc );

		if ( $wooLogin ) {
			$redirectTo = ! empty( $_POST['redirect'] )
				? wp_unslash( $_POST['redirect'] )
				: ( function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'myaccount' ) : admin_url() );
		} elseif ( isset( $_REQUEST['redirect_to'] ) ) {
			$redirectTo = wp_unslash( $_REQUEST['redirect_to'] );
		} elseif ( ! function_exists( 'login_header' ) && wp_get_referer() ) {
			$redirectTo = wp_get_referer();
		} else {
			$redirectTo = admin_url();
		}

		$this->render_challenge( $account, $nonce, $redirectTo );
		exit;
	}

	/**
	 * XML-RPC policy for enrolled accounts (twofa_xmlrpc_mode).
	 *
	 * There is no challenge screen on an XML-RPC request, so WordPress's plain
	 * username+password login there would bypass 2FA for an enrolled account.
	 * Modes: 'allow' (WordPress default — the neutral activation value),
	 * 'code' (the password must carry the 6-digit TOTP or a recovery code
	 * appended at the end, e.g. "mypassword123456"), 'block' (reject).
	 *
	 * Scope is deliberately narrow:
	 *  - Only XMLRPC_REQUEST. WP-CLI, cron, AJAX and REST pass through
	 *    untouched, so internal/programmatic flows can never break.
	 *  - Only accounts that have enrolled in 2FA.
	 *  - Application-password logins are exempt: each app password is its own
	 *    random revocable credential, not the account password this policy
	 *    guards (mirrors WP core treating them as an independent auth system).
	 *  - Suspended by the same kill-switches as the challenge (enforced()).
	 */
	private function apply_xmlrpc_policy( $user, $username, $password ) {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return $user;
		}

		$mode = (string) $this->settings->get( 'twofa_xmlrpc_mode', 'allow' );
		if ( ! in_array( $mode, array( 'code', 'block' ), true ) ) {
			return $user;
		}

		$account = get_user_by( 'login', $username );
		if ( ! $account && is_email( $username ) ) {
			$account = get_user_by( 'email', $username );
		}
		if ( ! $account || ! $this->user_has_2fa( $account->ID ) ) {
			return $user;
		}

		// An application password authenticated this request — its own
		// credential system, out of this policy's scope.
		if ( did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}

		if ( 'block' === $mode ) {
			QevixShield_Audit_Log::log( array( 'action' => '2fa_xmlrpc_blocked', 'severity' => 'warning', 'module' => 'auth', 'status' => 'blocked', 'user_id' => $account->ID ) );
			return new WP_Error(
				'qevix_shield_2fa_xmlrpc',
				__( 'XML-RPC sign-in is not available for accounts protected by two-factor authentication on this site.', 'qevix-shield' )
			);
		}

		// 'code' mode: the submitted password must be <password><code>. The
		// password half is verified FIRST (against core's own credential
		// checks), so a recovery code is only ever consumed by its real owner.
		$candidates = array();
		if ( preg_match( '/^(?<pwd>.+?)(?<code>[0-9]{6})$/s', (string) $password, $m ) ) {
			$candidates[] = array( $m['pwd'], $m['code'] ); // TOTP.
		}
		if ( preg_match( '/^(?<pwd>.+?)(?<code>[0-9a-f]{4}-?[0-9a-f]{4})$/is', (string) $password, $m ) ) {
			$candidates[] = array( $m['pwd'], $m['code'] ); // recovery code.
		}

		foreach ( $candidates as $candidate ) {
			list( $pwd, $code ) = $candidate;
			$check = wp_authenticate_username_password( null, $username, $pwd );
			if ( ! ( $check instanceof WP_User ) ) {
				$check = wp_authenticate_email_password( null, $username, $pwd );
			}
			if ( $check instanceof WP_User && (int) $check->ID === (int) $account->ID
				&& $this->verify_second_factor( $account, $code ) ) {
				QevixShield_Audit_Log::log( array( 'action' => '2fa_xmlrpc_verified', 'severity' => 'info', 'module' => 'auth', 'status' => 'success', 'user_id' => $account->ID ) );
				return $check;
			}
		}

		QevixShield_Audit_Log::log( array( 'action' => '2fa_xmlrpc_failed', 'severity' => 'warning', 'module' => 'auth', 'status' => 'blocked', 'user_id' => $account->ID ) );
		return new WP_Error(
			'qevix_shield_2fa_xmlrpc',
			__( 'Two-factor authentication is required: append the current 6-digit code from your authenticator app (or a recovery code) to the end of your password.', 'qevix-shield' )
		);
	}

	/**
	 * True for a WooCommerce front-end login form POST (my-account page or the
	 * checkout login form).
	 */
	private function is_woo_login_post() {
		return class_exists( 'WooCommerce' )
			&& isset( $_POST['login'], $_POST['username'], $_POST['password'] )
			&& ( isset( $_POST['woocommerce-login-nonce'] ) || isset( $_POST['_wpnonce'] ) );
	}

	/**
	 * Stores a fresh hashed login nonce (10-min expiry). $pwdEnc, when
	 * non-empty, is the AES-GCM-encrypted screen-1 password riding along so
	 * handle_challenge() can run the real credential check after the OTP.
	 */
	private function issue_login_nonce( $userId, $pwdEnc = '' ) {
		$nonce = wp_generate_password( 24, false );
		$data  = array(
			'hash' => wp_hash_password( $nonce ),
			'exp'  => time() + 10 * MINUTE_IN_SECONDS,
		);
		if ( '' !== $pwdEnc ) {
			$data['pwd'] = $pwdEnc;
		}
		update_user_meta( $userId, self::META_NONCE, $data );
		return $nonce;
	}

	/**
	 * Asks the free plugin's rate limiter (and anything else on the authenticate
	 * filter) whether this IP is currently locked out, without evaluating any
	 * credentials — so a locked-out IP can't keep brute-forcing codes on the
	 * challenge screen.
	 */
	private function ip_is_locked_out() {
		$probe = apply_filters( 'authenticate', null, '', '' );
		return is_wp_error( $probe ) && in_array( 'qevix_shield_locked_out', $probe->get_error_codes(), true );
	}

	/**
	 * Hooked on wp_login_errors: shows the post-OTP credential failure (the
	 * final password check in handle_challenge() redirects back to the login
	 * screen with this flag — a GET, so the error can't ride the POST).
	 */
	public function filter_login_errors( $errors ) {
		if ( isset( $_GET['qevix_shield_2fa_error'] ) && 'badcreds' === $_GET['qevix_shield_2fa_error'] && is_wp_error( $errors ) ) {
			$errors->add( 'qevix_shield_2fa_badcreds', __( '<strong>Error</strong>: Invalid username or password.', 'qevix-shield' ) );
		}
		return $errors;
	}

	/**
	 * Hooked on login_form_qevix_shield_2fa (the challenge form posts here). The
	 * OTP is verified first, and only then does the full credential check
	 * (wp_authenticate) run. Cookies/session are generated exclusively on the
	 * success of that final check.
	 */
	public function handle_challenge() {
		$userId = isset( $_POST['qevix_shield_2fa_user'] ) ? (int) $_POST['qevix_shield_2fa_user'] : 0;
		$nonce  = isset( $_POST['qevix_shield_2fa_nonce'] ) ? (string) wp_unslash( $_POST['qevix_shield_2fa_nonce'] ) : '';
		$user   = $userId ? get_user_by( 'id', $userId ) : false;

		if ( ! $user || ! $this->valid_login_nonce( $userId, $nonce ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// A locked-out IP doesn't get to keep guessing codes either.
		if ( $this->ip_is_locked_out() ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Grab the carried (encrypted) screen-1 password BEFORE any nonce
		// re-issue overwrites the meta row.
		$stored = get_user_meta( $userId, self::META_NONCE, true );
		$pwdEnc = ( is_array( $stored ) && ! empty( $stored['pwd'] ) ) ? (string) $stored['pwd'] : '';

		$method = isset( $_POST['qevix_shield_2fa_method'] ) ? sanitize_key( wp_unslash( $_POST['qevix_shield_2fa_method'] ) ) : 'totp';

		// User asked us to email a one-time code instead of using TOTP (pro).
		if ( 'email_send' === $method && $this->email_fallback_enabled() ) {
			do_action( 'qevix_shield_2fa_send_code', $user );
			$fresh = $this->issue_login_nonce( $userId, $pwdEnc );
			$this->render_challenge( $user, $fresh, $this->safe_redirect_target(), '', true );
			exit;
		}

		$code = isset( $_POST['qevix_shield_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['qevix_shield_2fa_code'] ) ) : '';

		if ( $this->verify_second_factor( $user, $code ) ) {
			delete_user_meta( $userId, self::META_NONCE );

			// OTP verified — NOW run the real username+password check.
			$password = '' !== $pwdEnc ? QevixShield_Crypto::decrypt( $pwdEnc ) : false;

			$this->completing_challenge = true;
			$auth                       = ( false !== $password && '' !== $password )
				? wp_authenticate( $user->user_login, $password )
				: new WP_Error( 'qevix_shield_2fa_nopwd' );
			$this->completing_challenge = false;

			if ( ! ( $auth instanceof WP_User ) ) {
				QevixShield_Audit_Log::log( array( 'action' => '2fa_failed', 'severity' => 'warning', 'module' => 'auth', 'status' => 'failed', 'user_id' => $userId ) );
				wp_safe_redirect( add_query_arg( 'qevix_shield_2fa_error', 'badcreds', wp_login_url() ) );
				exit;
			}

			if ( ! empty( $_POST['qevix_shield_2fa_trust'] ) ) {
				do_action( 'qevix_shield_2fa_trust_device', $userId );
			}

			$remember = ! empty( $_POST['rememberme'] );
			wp_set_auth_cookie( $userId, $remember );
			wp_set_current_user( $userId );

			// intercept_authentication() ended the screen-1 request before
			// wp_signon() completed, so core never fired wp_login for this
			// sign-in. Fire it now so everything listening sees the login.
			do_action( 'wp_login', $user->user_login, $user );

			QevixShield_Audit_Log::log( array( 'action' => '2fa_success', 'severity' => 'info', 'module' => 'auth', 'status' => 'success', 'user_id' => $userId ) );

			wp_safe_redirect( $this->safe_redirect_target() );
			exit;
		}

		QevixShield_Audit_Log::log( array( 'action' => '2fa_failed', 'severity' => 'warning', 'module' => 'auth', 'status' => 'failed', 'user_id' => $userId ) );

		// A wrong code is a failed login attempt: let the free rate limiter count
		// it so the OTP can't be brute-forced.
		do_action( 'wp_login_failed', $user->user_login, new WP_Error( 'qevix_shield_2fa_invalid', __( 'Invalid two-factor code.', 'qevix-shield' ) ) );

		// Re-issue a fresh nonce (carrying the password forward) and re-render.
		$fresh = $this->issue_login_nonce( $userId, $pwdEnc );
		$this->render_challenge( $user, $fresh, $this->safe_redirect_target(), __( 'Invalid code. Please try again.', 'qevix-shield' ) );
		exit;
	}

	private function safe_redirect_target() {
		$requested = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url();
		return wp_validate_redirect( $requested, admin_url() );
	}

	private function valid_login_nonce( $userId, $nonce ) {
		$stored = get_user_meta( $userId, self::META_NONCE, true );
		if ( ! is_array( $stored ) || empty( $stored['hash'] ) || empty( $stored['exp'] ) ) {
			return false;
		}
		if ( time() > (int) $stored['exp'] ) {
			return false;
		}
		return wp_check_password( $nonce, $stored['hash'] );
	}

	/** Accepts a TOTP code, a one-time recovery code, or (pro) an emailed code. */
	private function verify_second_factor( $user, $code ) {
		$secret = $this->get_secret( $user->ID );
		if ( '' !== $secret && QevixShield_TOTP::verify( $secret, $code ) ) {
			return true;
		}
		if ( $this->consume_recovery_code( $user->ID, $code ) ) {
			return true;
		}
		if ( (bool) apply_filters( 'qevix_shield_2fa_alt_verify', false, $user->ID, $code ) ) {
			return true;
		}
		return false;
	}

	private function consume_recovery_code( $userId, $code ) {
		$code   = strtoupper( trim( (string) $code ) );
		$hashes = (array) get_user_meta( $userId, self::META_RECOVERY, true );
		foreach ( $hashes as $i => $hash ) {
			if ( password_verify( $code, $hash ) ) {
				unset( $hashes[ $i ] ); // one-time use.
				update_user_meta( $userId, self::META_RECOVERY, array_values( $hashes ) );
				return true;
			}
		}
		return false;
	}

	/**
	 * Renders the interim second-factor form. Inside the wp-login.php request
	 * lifecycle login_header()/login_footer() wrap the shared view; on a
	 * WooCommerce front-end login POST (wp-login.php never loaded) the same view
	 * is wrapped in a minimal self-contained shell.
	 */
	private function render_challenge( $user, $nonce, $redirectTo, $error = '', $emailSent = false ) {
		$emailFallback   = $this->email_fallback_enabled();
		$trustedDevices  = $this->trusted_devices_enabled();
		// Display-only: the configured trust duration for the checkbox label.
		// Pro supplies its saved twofa_trusted_days; the default never shows,
		// since the checkbox itself only renders when pro enables it above.
		$trustedDays     = max( 1, (int) apply_filters( 'qevix_shield_2fa_trusted_days', 30 ) );

		if ( function_exists( 'login_header' ) ) {
			login_header( __( 'Two-Factor Authentication', 'qevix-shield' ) );
			include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/twofa-challenge.php';
			login_footer();
			return;
		}

		nocache_headers();
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="robots" content="noindex, nofollow" />
	<title><?php echo esc_html( sprintf( /* translators: %s site name */ __( 'Two-Factor Authentication — %s', 'qevix-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ) ); ?></title>
	<?php
	// Self-contained shell (wp-login.php never loaded — a WooCommerce front-end
	// login POST), so there is no enqueue pass: register + print the shared
	// login-forms stylesheet rather than emitting a raw <style> tag.
	wp_register_style( 'qevix-shield-login-forms', QEVIX_SHIELD_PLUGIN_URL . 'assets/css/login-forms.css', array(), QEVIX_SHIELD_VERSION );
	wp_print_styles( 'qevix-shield-login-forms' );
	?>
</head>
<body>
	<div class="qevix-shield-2fa-box">
		<h1><?php esc_html_e( 'Two-Factor Authentication', 'qevix-shield' ); ?></h1>
		<?php include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/twofa-challenge.php'; ?>
	</div>
</body>
</html>
		<?php
	}

	/* ========================= admin reset ========================== */

	/** Hooked on edit_user_profile: reset button for other users. */
	public function render_admin_reset_field( $user ) {
		if ( ! current_user_can( 'edit_users' ) ) {
			return;
		}
		$has = $this->user_has_2fa( $user->ID );
		?>
		<h2><?php esc_html_e( 'Qevix Shield Two-Factor Authentication', 'qevix-shield' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Status', 'qevix-shield' ); ?></th>
				<td>
					<?php if ( $has ) : ?>
						<p><?php esc_html_e( 'This user has two-factor authentication enabled.', 'qevix-shield' ); ?></p>
						<label><input type="checkbox" name="qevix_shield_2fa_reset" value="1" /> <?php esc_html_e( 'Reset (disable) this user\'s 2FA on save', 'qevix-shield' ); ?></label>
					<?php else : ?>
						<p><?php esc_html_e( 'This user does not have two-factor authentication enabled.', 'qevix-shield' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
		wp_nonce_field( 'qevix_shield_2fa_admin_reset', 'qevix_shield_2fa_admin_reset_nonce' );
	}

	public function handle_admin_reset( $userId ) {
		if ( ! current_user_can( 'edit_user', $userId ) ) {
			return;
		}
		if ( ! isset( $_POST['qevix_shield_2fa_admin_reset_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['qevix_shield_2fa_admin_reset_nonce'] ) ), 'qevix_shield_2fa_admin_reset' ) ) {
			return;
		}
		if ( ! empty( $_POST['qevix_shield_2fa_reset'] ) ) {
			$this->reset_user( $userId );
			QevixShield_Audit_Log::log( array( 'action' => '2fa_admin_reset', 'severity' => 'warning', 'module' => 'admin', 'status' => 'success', 'user_id' => $userId ) );
		}
	}

	/**
	 * Public reset entry point (WP-CLI / programmatic): disable and wipe a
	 * user's 2FA enrollment. Callers are responsible for their own authorization.
	 */
	public function reset( $userId ) {
		$this->reset_user( (int) $userId );
	}

	private function reset_user( $userId ) {
		delete_user_meta( $userId, self::META_SECRET );
		delete_user_meta( $userId, self::META_ENABLED );
		delete_user_meta( $userId, self::META_RECOVERY );
		delete_user_meta( $userId, self::META_NONCE );
		// Pro clears its own per-user data (trusted devices, emailed-code state).
		do_action( 'qevix_shield_2fa_reset_user', (int) $userId );
	}
}
