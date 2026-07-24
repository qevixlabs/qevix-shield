<?php
/**
 * Google reCAPTCHA.
 *
 * This plugin implements BOTH versions — v2 ("I'm not a robot") and invisible
 * v3 with a score threshold — plus the email verification fallback, on the
 * wp-login Login, Registration and Lost Password forms. All of it is available
 * on every tier: nothing here is gated on a licence (wp.org Guideline 5).
 * The qevix_shield_recaptcha_* filters remain public extension points, and the
 * render/verify methods are public, so a companion plugin can hook them onto
 * forms this plugin does not render (WooCommerce, other plugins' forms).
 *
 * Fails open on a Google outage — the rate limiter and honeypot still apply.
 * A mismatched key can never lock anyone out: it can't be enabled until the
 * "Test keys" preflight passes, and active() refuses to enforce an unverified
 * config. Safe Mode and the disable constants are the last-resort hatch.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Recaptcha {

	const FIELD      = 'qevix_shield_recaptcha_token';
	const VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

	/**
	 * Email sign-in verification (v3 login form only).
	 * A human the score check rejects gets a one-time emailed link instead of a
	 * dead end; the link carries VERIFY_PARAM, the login form re-posts it as
	 * VERIFY_FIELD, and a match against META_VERIFY exempts that attempt from
	 * the captcha verdict ONLY — password (and 2FA) still apply in full.
	 */
	const VERIFY_PARAM   = 'qevix_shield_verify';                 // GET, from the emailed link.
	const VERIFY_FIELD   = 'qevix_shield_login_verify';           // hidden POST field on the form.
	const META_VERIFY    = 'qevix_shield_recaptcha_verify';       // user meta: ['hash','exp'].
	const VERIFY_TTL     = 900;                                 // link lifetime (15 min).
	const VERIFY_RL_TTL  = 600;                                 // min gap between emails per account (10 min).

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * wp-config kill-switches, any one of which suspends reCAPTCHA site-wide:
	 * QEVIX_SHIELD_SAFE_MODE (the master hatch), QEVIX_SHIELD_DISABLE_RECAPTCHA, or
	 * QEVIX_SHIELD_PRO_DISABLE_RECAPTCHA (kept for back-compat). A file-level way
	 * back in for a locked-out admin. Not filterable — that would defeat it.
	 */
	public static function is_bypassed() {
		if ( class_exists( 'QevixShield' ) && QevixShield::is_safe_mode() ) {
			return true;
		}
		if ( defined( 'QEVIX_SHIELD_DISABLE_RECAPTCHA' ) && QEVIX_SHIELD_DISABLE_RECAPTCHA ) {
			return true;
		}
		return defined( 'QEVIX_SHIELD_PRO_DISABLE_RECAPTCHA' ) && QEVIX_SHIELD_PRO_DISABLE_RECAPTCHA;
	}

	/**
	 * Cheap format check for a reCAPTCHA key (starts "6L", ~40 URL-safe chars),
	 * to catch an obvious mis-paste without calling Google. It can't tell v2
	 * from v3 — that only shows when the widget renders. Empty = no opinion.
	 */
	public static function looks_like_key( $key ) {
		$key = trim( (string) $key );
		if ( '' === $key ) {
			return true;
		}
		return (bool) preg_match( '/^6L[0-9A-Za-z_-]{20,}$/', $key );
	}

	/**
	 * Identity of one key config: site key + version + secret. Stored in
	 * `recaptcha_verified` once the trio passes "Test keys", and re-checked on
	 * save, so editing any of the three re-locks the master switch. Hashed
	 * because it includes the secret.
	 */
	public static function fingerprint( $siteKey, $version, $secret ) {
		return hash( 'sha256', trim( (string) $siteKey ) . '|' . $version . '|' . trim( (string) $secret ) );
	}

	/** True when the currently SAVED trio is the one that passed the preflight. */
	public function is_verified() {
		$stored = (string) $this->settings->get( 'recaptcha_verified', '' );
		if ( '' === $stored ) {
			return false;
		}
		return hash_equals(
			$stored,
			self::fingerprint(
				$this->settings->get( 'recaptcha_site_key', '' ),
				$this->version(),
				$this->settings->get( 'recaptcha_secret_key', '' )
			)
		);
	}

	/**
	 * siteverify errors that mean the SITE is broken, not the visitor (bad or
	 * absent secret, malformed request). Every human fails these too, so we fail
	 * OPEN on them, like an outage. Everything else (invalid-input-response,
	 * timeout-or-duplicate, a low score) is a verdict on the request — fail closed.
	 */
	const CONFIG_ERRORS = array(
		'invalid-input-secret',
		'missing-input-secret',
		'invalid-keys',
		'bad-request',
	);

	/* -------------------- Preflight ("Test keys") -------------------- */

	/**
	 * Is this a v3 site key? Fetches the v3 loader URL the browser uses.
	 * Measured: Google answers 400 for a registered non-v3 (i.e. v2) key, and
	 * 200 for a v3 key OR an unregistered/garbage/demo key. So a 400 proves
	 * "registered, not v3"; a 200 proves nothing. Lets us diagnose a browser
	 * script-load failure server-side without ever inventing a verdict.
	 *
	 * @return string 'not_v3' | 'unreachable' | 'inconclusive'
	 */
	private function probe_v3_render( $siteKey ) {
		$response = wp_remote_get(
			'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $siteKey ),
			array( 'timeout' => 10 )
		);
		if ( is_wp_error( $response ) ) {
			return 'unreachable';
		}
		return 400 === (int) wp_remote_retrieve_response_code( $response ) ? 'not_v3' : 'inconclusive';
	}

	/**
	 * This site's origin, in the scheme://host:port form Google's widget reports
	 * itself as running on.
	 */
	private function site_origin() {
		$parts  = wp_parse_url( home_url() );
		$scheme = isset( $parts['scheme'] ) ? $parts['scheme'] : 'http';
		$host   = isset( $parts['host'] ) ? $parts['host'] : '';
		$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
		return $scheme . '://' . $host . ':' . $port;
	}

	/**
	 * Is this site's domain on the key's allowed list? Fetches the widget Google
	 * would render for this key at this origin: an unlisted domain returns a
	 * short "Invalid domain" page, an allowed one the real ~39KB widget markup.
	 * Only the explicit "Invalid domain" marker yields 'not_allowed' — the
	 * endpoint is undocumented, so anything else stays 'inconclusive' rather
	 * than risk sending the admin to fix a domain list that was already fine.
	 *
	 * @return string 'not_allowed' | 'allowed' | 'inconclusive'
	 */
	private function probe_domain( $siteKey ) {
		$co = rtrim( strtr( base64_encode( $this->site_origin() ), '+/', '-_' ), '=' );

		$response = wp_remote_get(
			'https://www.google.com/recaptcha/api2/anchor?ar=1&k=' . rawurlencode( $siteKey )
				. '&co=' . $co . '&hl=en&size=normal&type=image',
			array( 'timeout' => 10 )
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return 'inconclusive';
		}

		$body = (string) wp_remote_retrieve_body( $response );
		if ( false !== stripos( $body, 'Invalid domain' ) ) {
			return 'not_allowed';
		}
		// The real widget carries the checkbox anchor markup.
		return false !== stripos( $body, 'rc-anchor' ) ? 'allowed' : 'inconclusive';
	}

	/**
	 * Why did the widget mint no token? Only ever names a cause a probe actually
	 * confirmed (key type via probe_v3_render, domain via probe_domain) — a wrong
	 * guess sends the admin fixing something that was fine. For v2, no token is
	 * just the state before the box is ticked, not a fault.
	 */
	private function explain_missing_token( $siteKey, $version, $domainProbe = null ) {
		$probe = $this->probe_v3_render( $siteKey );

		if ( 'unreachable' === $probe ) {
			return __( 'This server could not reach google.com to check the key. If the site sits behind a firewall or proxy that blocks outbound requests, reCAPTCHA cannot work until google.com is reachable.', 'qevix-shield' );
		}

		// Key type is wrong — the one cause we can name with certainty.
		if ( 'v3' === $version && 'not_v3' === $probe ) {
			return __( 'Google rejects this Site Key for v3 — it is a v2 key. Either set the Version to v2, or save the Site Key from a "Score based (v3)" entry in the Google reCAPTCHA console. The two types are not interchangeable, and the secret must come from the same entry as the site key.', 'qevix-shield' );
		}
		if ( 'v2' === $version && 'inconclusive' === $probe ) {
			return __( 'Google refused this Site Key for the v2 checkbox — it is almost certainly a v3 key. Either set the Version to v3, or save the Site Key from an "I\'m not a robot Checkbox (v2)" entry in the Google reCAPTCHA console.', 'qevix-shield' );
		}

		// Key type checks out, so only blame the domain if it's genuinely wrong.
		// Reuse the caller's probe when it ran one (ajax_test does for v2).
		$domain = ( null !== $domainProbe ) ? $domainProbe : $this->probe_domain( $siteKey );
		if ( 'not_allowed' === $domain ) {
			return sprintf(
				/* translators: %s: this site's origin, e.g. http://example.com:80 */
				__( 'Google rejects this Site Key for %s — this site\'s domain is not on the key\'s allowed list. Add it under Domains for this key in the Google reCAPTCHA console.', 'qevix-shield' ),
				$this->site_origin()
			);
		}

		// Nothing is demonstrably wrong. For v2 that is the ordinary state
		// before the box is ticked — say what to do, do not invent a fault.
		if ( 'v2' === $version ) {
			return __( 'The checkbox loaded correctly — the key, version and domain all check out. Tick the "I\'m not a robot" box to finish the test. If you ticked it and still see this, something in the browser (an ad blocker or privacy extension) is blocking google.com.', 'qevix-shield' );
		}
		return __( 'The key, version and domain all check out, but Google returned no v3 token. This is usually a browser extension (ad blocker or privacy tool) blocking google.com — try again in a private window with extensions disabled.', 'qevix-shield' );
	}

	/**
	 * "Test keys" (wp_ajax_qevix_shield_recaptcha_test): verify a token the admin's
	 * browser just minted with the SAVED trio and, on success, record the
	 * fingerprint that unlocks the master switch. This is the only place a v2/v3
	 * mismatch can be caught — at login time an unrendered widget and a stripped
	 * token both arrive as an empty field. The trio is read from settings, not
	 * the request (save first, then test), so the fingerprint always describes
	 * the stored config and the browser controls only the token.
	 */
	public function ajax_test() {
		if ( ! current_user_can( QevixShield_Settings::CAP ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission to do this.', 'qevix-shield' ) ), 403 );
		}
		check_ajax_referer( 'qevix_shield_recaptcha_test' );

		$siteKey = trim( (string) $this->settings->get( 'recaptcha_site_key', '' ) );
		$secret  = trim( (string) $this->settings->get( 'recaptcha_secret_key', '' ) );
		$version = $this->version();
		$token   = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';

		if ( '' === $siteKey || '' === $secret ) {
			wp_send_json_error( array( 'message' => __( 'Save a Site Key and a Secret Key first, then test.', 'qevix-shield' ) ) );
		}

		// Domain gate (v2). A key whose domain list doesn't cover this site
		// rejects every visitor, so it must fail the preflight like a wrong key
		// type does — otherwise the fingerprint records and Enable unlocks a
		// config that would lock the login form. Only Google's explicit "Invalid
		// domain" blocks (see probe_domain). v2 only: the probe queries the v2
		// endpoint; for v3 an unlisted domain is caught by siteverify instead.
		// Pass the result to explain_missing_token so it doesn't re-probe.
		$domainProbe = null;
		if ( 'v2' === $version ) {
			$domainProbe = $this->probe_domain( $siteKey );
			if ( 'not_allowed' === $domainProbe ) {
				wp_send_json_error( array( 'message' => sprintf(
					/* translators: 1: this site's origin, 2: this site's origin (again) */
					__( 'This site (%1$s) is not on the Site Key\'s allowed-domain list in the Google reCAPTCHA console, so reCAPTCHA would reject every visitor and lock the login form — including you. Open this key in the console, add %2$s under Domains, save there, then test again.', 'qevix-shield' ),
					$this->site_origin(),
					$this->site_origin()
				) ) );
			}
		}

		// The browser produced no token — the widget/script itself failed. The
		// browser cannot say why (a failed <script> exposes no status code), so
		// ask Google directly rather than guessing at the cause.
		if ( '' === $token ) {
			wp_send_json_error( array( 'message' => $this->explain_missing_token( $siteKey, $version, $domainProbe ) ) );
		}

		$data = $this->siteverify( $token, $secret );

		if ( is_wp_error( $data ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not reach Google to verify the key. Check the server\'s outbound connection and try again.', 'qevix-shield' ) ) );
		}

		if ( empty( $data['success'] ) ) {
			$codes = isset( $data['error-codes'] ) ? (array) $data['error-codes'] : array();

			if ( in_array( 'invalid-input-secret', $codes, true ) || in_array( 'missing-input-secret', $codes, true ) ) {
				wp_send_json_error( array( 'message' => __( 'The Site Key works, but Google rejected the Secret Key. Re-copy the secret from the same console page as this site key — a secret from a different key pair will not work.', 'qevix-shield' ) ) );
			}
			if ( in_array( 'invalid-input-response', $codes, true ) ) {
				wp_send_json_error( array( 'message' => __( 'The Site Key and Secret Key do not belong to the same key pair. Both must be copied from the same entry in the Google reCAPTCHA console.', 'qevix-shield' ) ) );
			}
			wp_send_json_error(
				array(
					'message' => sprintf(
						/* translators: %s: comma-separated Google error codes */
						__( 'Google rejected the test: %s', 'qevix-shield' ),
						$codes ? implode( ', ', array_map( 'sanitize_text_field', $codes ) ) : __( 'unknown error', 'qevix-shield' )
					),
				)
			);
		}

		$this->settings->update(
			array( 'recaptcha_verified' => self::fingerprint( $siteKey, $version, $secret ) )
		);

		$score = isset( $data['score'] ) ? (float) $data['score'] : null;

		wp_send_json_success(
			array(
				'message' => null !== $score
					? sprintf(
						/* translators: 1: version, 2: score */
						__( 'Keys verified — reCAPTCHA %1$s is working (this request scored %2$s). You can now turn reCAPTCHA on and save.', 'qevix-shield' ),
						$version,
						number_format_i18n( $score, 1 )
					)
					: sprintf(
						/* translators: %s: version */
						__( 'Keys verified — reCAPTCHA %s is working. You can now turn reCAPTCHA on and save.', 'qevix-shield' ),
						$version
					),
			)
		);
	}

	private function active() {
		if ( self::is_bypassed() ) {
			return false;
		}
		$configured = $this->settings->get( 'recaptcha_enabled', false )
			&& '' !== (string) $this->settings->get( 'recaptcha_site_key', '' )
			&& '' !== (string) $this->settings->get( 'recaptcha_secret_key', '' );

		// Also require a config that passed "Test keys". A saved trio can drift
		// out of verification with no re-test (e.g. the Version ends up v3, pro's
		// default, over a v2 key) — the widget then mints no token and enforcing
		// it would fail closed and lock everyone out. is_verified() is a local
		// hash compare, so gating on it here leaves such a config inert (safe
		// fail-open) until the admin re-tests, instead of enforcing it blind.
		return $configured && $this->is_verified();
	}

	private function protects( $form ) {
		$forms = (array) $this->settings->get( 'recaptcha_forms', array( 'login' ) );
		return in_array( $form, $forms, true );
	}

	/**
	 * 'v2' (visible "I'm not a robot" checkbox) or 'v3' (invisible, score-based).
	 * Owned by this plugin's own setting — both versions are available on the
	 * free tier. The filter is kept as a public extension point (a site or
	 * another plugin may pin the version programmatically); it is deliberately
	 * NOT a licence gate.
	 */
	private function version() {
		$stored = (string) $this->settings->get( 'recaptcha_version', 'v2' );
		$stored = in_array( $stored, array( 'v2', 'v3' ), true ) ? $stored : 'v2';

		return 'v3' === apply_filters( 'qevix_shield_recaptcha_version', $stored ) ? 'v3' : 'v2';
	}

	/** v3 pass threshold (0.0–1.0), configurable on every tier. */
	private function threshold() {
		$stored = (float) $this->settings->get( 'recaptcha_threshold', 0.5 );
		$stored = ( $stored >= 0 && $stored <= 1 ) ? $stored : 0.5;

		return (float) apply_filters( 'qevix_shield_recaptcha_threshold', $stored );
	}

	/** Maps the current wp-login.php ?action= to our form keys ('' = a view we don't protect). */
	private function current_form() {
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		if ( 'retrievepassword' === $action ) { // core alias for lostpassword.
			$action = 'lostpassword';
		}
		return in_array( $action, array( 'login', 'register', 'lostpassword' ), true ) ? $action : '';
	}

	/** Hooked on login_enqueue_scripts (fires for every wp-login.php view). */
	public function enqueue() {
		$form = $this->current_form();
		if ( '' === $form || ! $this->active() || ! $this->protects( $form ) ) {
			return;
		}
		$this->enqueue_api_script();
	}

	/**
	 * Hooked (by pro) on wp_enqueue_scripts: the WooCommerce my-account page
	 * hosts the login/register/lost-password forms front-end — load the API
	 * there when any form is protected.
	 */
	public function enqueue_frontend() {
		if ( ! $this->active() ) {
			return;
		}
		$forms = (array) $this->settings->get( 'recaptcha_forms', array( 'login' ) );
		if ( empty( $forms ) ) {
			return;
		}

		$load = class_exists( 'WooCommerce' ) && ( is_account_page() || is_checkout() );

		/**
		 * Load the reCAPTCHA API script on additional front-end pages (ones
		 * where a bridge action renders the field into a custom form).
		 *
		 * @param bool $load Whether the current page needs the API script.
		 */
		if ( ! apply_filters( 'qevix_shield_recaptcha_enqueue', $load ) ) {
			return;
		}
		$this->enqueue_api_script();
	}

	private function enqueue_api_script() {
		$siteKey = $this->settings->get( 'recaptcha_site_key' );
		$src     = 'v2' === $this->version()
			? 'https://www.google.com/recaptcha/api.js' // auto-renders .g-recaptcha widgets.
			: 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $siteKey );
		// Version is deliberately null: this is Google's own remotely-hosted api.js,
		// and appending our ?ver= to a third-party URL would be wrong (it is not our
		// asset to cache-bust, and the query string is part of their contract).
		wp_enqueue_script( 'qevix-shield-recaptcha-api', $src, array(), null, true ); // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- third-party Google api.js; version intentionally null (not our asset to cache-bust).
	}

	/** Hooked on login_form (and, via pro, woocommerce_login_form). */
	public function render_field() {
		$this->output_field( 'login' );
	}

	/** Hooked on register_form (and, via pro, woocommerce_register_form). */
	public function render_register_field() {
		$this->output_field( 'register' );
	}

	/** Hooked on lostpassword_form (and, via pro, woocommerce_lostpassword_form). */
	public function render_lostpassword_field() {
		$this->output_field( 'lostpassword' );
	}

	/**
	 * v2: renders the visible "I'm not a robot" checkbox widget.
	 * v3: injects the hidden token field + the script that fills it.
	 */
	private function output_field( $form ) {
		if ( ! $this->active() || ! $this->protects( $form ) ) {
			return;
		}
		$siteKey = $this->settings->get( 'recaptcha_site_key' );

		// Unique id per instance — Woo's my-account page hosts login + register
		// together, so a fixed id would collide. The POST name stays the same
		// (only one form submits at a time).
		static $instance = 0;
		$instance++;
		$fieldId = self::FIELD . '_' . $instance;

		if ( 'v2' === $this->version() ) {
			?>
			<div class="g-recaptcha" data-sitekey="<?php echo esc_attr( $siteKey ); ?>" style="margin:0 0 16px;transform:scale(0.89);transform-origin:0 0;"></div>
			<?php
			return;
		}
		?>
		<input type="hidden" name="<?php echo esc_attr( self::FIELD ); ?>" id="<?php echo esc_attr( $fieldId ); ?>" value="" />
		<?php
		// Hand this instance's config to the enqueued refresher (assets/js/
		// recaptcha-v3.js) instead of emitting a raw <script>. Self-enqueue here
		// (idempotent) so the script is present wherever a v3 field renders — a
		// page may host several forms, each pushing its own config onto the array.
		wp_enqueue_script( 'qevix-shield-recaptcha-v3', QEVIX_SHIELD_PLUGIN_URL . 'assets/js/recaptcha-v3.js', array(), QEVIX_SHIELD_VERSION, true );
		wp_add_inline_script(
			'qevix-shield-recaptcha-v3',
			'window.QevixShieldRecaptchaV3 = window.QevixShieldRecaptchaV3 || []; window.QevixShieldRecaptchaV3.push('
				. wp_json_encode(
					array(
						'siteKey' => $siteKey,
						'action'  => $form,
						'fieldId' => $fieldId,
					)
				) . ');',
			'before'
		);
	}

	/**
	 * Hooked on authenticate (priority 25 — after WP core's own credential
	 * check at 20).
	 */
	public function verify( $user ) {
		if ( ! $this->active() || ! $this->protects( 'login' ) ) {
			return $user;
		}

		// Only gate POSTs from a form that actually rendered our field, or we'd
		// block logins that never had a token to send. Free covers wp-login.php
		// (posts `log`); pro adds its own forms through the filter below.
		$isFormPost = ! empty( $_POST ) && isset( $_POST['log'] );

		/**
		 * Extends reCAPTCHA login enforcement to additional forms. Only return
		 * true for a POST whose form also renders the token field.
		 *
		 * @param bool $isFormPost Whether this POST is a covered login form.
		 */
		$isFormPost = (bool) apply_filters( 'qevix_shield_recaptcha_login_post', $isFormPost );
		if ( ! $isFormPost ) {
			return $user;
		}

		// A valid emailed verification token exempts THIS attempt from the
		// captcha verdict only — the credential check (and any 2FA challenge,
		// which runs later on this same filter) still applies in full.
		if ( $this->email_verification_passes() ) {
			return $user;
		}

		return $this->token_passes() ? $user : $this->fail_login();
	}

	/* ------------- emailed sign-in verification (login form) ------------- */

	/** On when the version is v3 and the Email Verification Fallback setting is ticked. */
	private function email_fallback_enabled() {
		// v3 only — a v2 rejection just means "tick the box again", so there is
		// nothing to fall back from. Owned by this plugin's own setting; the
		// filter stays a public extension point, not a licence gate.
		if ( 'v3' !== $this->version() ) {
			return false;
		}
		$stored = (bool) $this->settings->get( 'recaptcha_email_fallback', false );

		return (bool) apply_filters( 'qevix_shield_recaptcha_email_fallback', $stored );
	}

	/** Resolve the account the login POST is for (login name or email). */
	private function posted_account() {
		$username = isset( $_POST['log'] ) ? (string) wp_unslash( $_POST['log'] ) : '';
		if ( '' === $username ) {
			return false;
		}
		$account = get_user_by( 'login', $username );
		if ( ! $account && is_email( $username ) ) {
			$account = get_user_by( 'email', $username );
		}
		return $account;
	}

	/**
	 * True when the POST carries a live emailed verification token for the
	 * account being signed in to. The token is expiry-bound (15 min) rather
	 * than consumed on first use: consuming it on a wrong-password attempt
	 * would burn the link and strand the user in a resend loop, and within
	 * its window it is useless without the account password anyway.
	 */
	private function email_verification_passes() {
		if ( ! $this->email_fallback_enabled() ) {
			return false;
		}
		$token = isset( $_POST[ self::VERIFY_FIELD ] ) ? (string) wp_unslash( $_POST[ self::VERIFY_FIELD ] ) : '';
		if ( '' === $token ) {
			return false;
		}
		$account = $this->posted_account();
		if ( ! $account ) {
			return false;
		}
		$stored = get_user_meta( $account->ID, self::META_VERIFY, true );
		if ( ! is_array( $stored ) || empty( $stored['hash'] ) || empty( $stored['exp'] ) ) {
			return false;
		}
		if ( time() > (int) $stored['exp'] || ! wp_check_password( $token, $stored['hash'] ) ) {
			return false;
		}
		QevixShield_Audit_Log::log( array( 'action' => 'recaptcha_verify_used', 'severity' => 'info', 'module' => 'auth', 'status' => 'allowed', 'user_id' => $account->ID ) );
		return true;
	}

	/**
	 * Login-form rejection. Without the fallback this is the plain captcha
	 * error; with it (pro, v3), the rejection stands but the account holder is
	 * emailed a one-time sign-in verification link — a human the score check
	 * misjudged has a way in, a bot gains nothing (the message and response
	 * are identical whether or not the username matched an account, and the
	 * link only reaches the account's own mailbox).
	 */
	private function fail_login() {
		if ( ! $this->email_fallback_enabled() ) {
			return $this->fail();
		}

		$account = $this->posted_account();
		if ( $account && false === get_transient( 'qevix_shield_rc_verify_rl_' . $account->ID ) ) {
			set_transient( 'qevix_shield_rc_verify_rl_' . $account->ID, 1, self::VERIFY_RL_TTL );
			$this->send_verification_email( $account );
		}

		return new WP_Error(
			'qevix_shield_recaptcha_verify',
			__( '<strong>Verification needed</strong>: this sign-in could not be confirmed as human. If the details you entered match an account, a sign-in verification link has been emailed to its address — open it and log in from there.', 'qevix-shield' )
		);
	}

	/** One-time link → user meta (hashed) + email via the shared template. */
	private function send_verification_email( $account ) {
		$token = wp_generate_password( 32, false );
		update_user_meta(
			$account->ID,
			self::META_VERIFY,
			array(
				'hash' => wp_hash_password( $token ),
				'exp'  => time() + self::VERIFY_TTL,
			)
		);

		$link = add_query_arg( self::VERIFY_PARAM, rawurlencode( $token ), wp_login_url() );

		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] Verify your sign-in', 'qevix-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		$explain = __( 'Someone — hopefully you — just tried to sign in to your account, but our automated-traffic protection could not confirm the attempt was human. This can happen on VPNs, strict privacy browsers, or shared networks.', 'qevix-shield' );
		$howto   = __( 'If that was you, open the link below and sign in from the page it takes you to. The link is valid for 15 minutes and skips only the bot check — your password is still required.', 'qevix-shield' );
		$ignore  = __( 'If you did not try to sign in, you can safely ignore this email — nobody got in.', 'qevix-shield' );

		$plain = $explain . "\n\n" . $howto . "\n\n" . $link . "\n\n" . $ignore;

		$p     = static function ( $text, $muted = false ) {
			return '<p style="margin:0 0 14px;font-size:14px;line-height:1.6;color:' . ( $muted ? '#646970' : '#3c434a' ) . ';">' . esc_html( $text ) . '</p>';
		};
		$inner = $p( $explain ) . $p( $howto )
			. '<p style="margin:0 0 14px;"><a href="' . esc_url( $link ) . '" style="display:inline-block;background:#2271b1;color:#ffffff;text-decoration:none;font-size:14px;padding:10px 18px;border-radius:3px;">' . esc_html__( 'Verify this sign-in', 'qevix-shield' ) . '</a></p>'
			. $p( $ignore, true );

		$html = QevixShield_Util::email_wrap( __( 'Verify your sign-in', 'qevix-shield' ), $inner );
		QevixShield_Util::send_html_mail( $account->user_email, $subject, $html, $plain );

		QevixShield_Audit_Log::log( array( 'action' => 'recaptcha_verify_sent', 'severity' => 'info', 'module' => 'auth', 'status' => 'ok', 'user_id' => $account->ID ) );
	}

	/**
	 * Carries the emailed token through the login form: arriving via the link
	 * puts it in the URL (VERIFY_PARAM); a re-rendered form after e.g. a wrong
	 * password re-posts it (VERIFY_FIELD). Hooked on login_form alongside the
	 * captcha field render.
	 */
	public function render_verification_field() {
		if ( ! $this->email_fallback_enabled() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the token itself is the credential being relayed; it is validated server-side on POST.
		$token = isset( $_REQUEST[ self::VERIFY_PARAM ] ) ? (string) wp_unslash( $_REQUEST[ self::VERIFY_PARAM ] ) : '';
		if ( '' === $token && isset( $_POST[ self::VERIFY_FIELD ] ) ) {
			$token = (string) wp_unslash( $_POST[ self::VERIFY_FIELD ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the reCAPTCHA token is itself the credential and is validated server-side.
		}
		if ( '' === $token ) {
			return;
		}
		echo '<input type="hidden" name="' . esc_attr( self::VERIFY_FIELD ) . '" value="' . esc_attr( $token ) . '" />';
	}

	/** Friendly banner on the login screen when arriving from the email link. */
	public function verification_login_message( $message ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		if ( $this->email_fallback_enabled() && isset( $_GET[ self::VERIFY_PARAM ] ) ) {
			$message .= '<p class="message">' . esc_html__( 'Verification link opened — enter your username and password below to finish signing in.', 'qevix-shield' ) . '</p>';
		}
		return $message;
	}

	/**
	 * Hooked (by pro) on woocommerce_register_post. Gated on that form's own
	 * nonce so programmatic wc_create_new_customer() calls are left alone.
	 */
	public function verify_woo_registration( $username, $email, $errors ) {
		if ( ! $this->active() || ! $this->protects( 'register' ) ) {
			return;
		}
		if ( ! ( $errors instanceof WP_Error ) || ! isset( $_POST['woocommerce-register-nonce'] ) ) {
			return;
		}
		if ( ! $this->token_passes() ) {
			$errors->add( 'qevix_shield_recaptcha', $this->fail_message() );
		}
	}

	/**
	 * Hooked on registration_errors (priority 25, after core's own checks).
	 */
	public function verify_registration( $errors, $sanitized_user_login = '', $user_email = '' ) {
		if ( ! is_wp_error( $errors ) || ! $this->active() || ! $this->protects( 'register' ) ) {
			return $errors;
		}
		if ( empty( $_POST ) || ! isset( $_POST['user_login'], $_POST['user_email'] ) ) {
			return $errors;
		}
		if ( ! $this->token_passes() ) {
			$errors->add( 'qevix_shield_recaptcha', $this->fail_message() );
		}
		return $errors;
	}

	/**
	 * Hooked on lostpassword_post. Core checks $errors->has_errors() right after
	 * this action, so adding an error blocks the reset email.
	 */
	public function verify_lostpassword( $errors, $user_data = null ) {
		// wp-login.php and Woo's my-account form fire this same hook, but free
		// only renders the field on wp-login.php. login_header() exists only
		// while wp-login.php is running, so it scopes free enforcement to that
		// form; pro covers the Woo/custom surface via enforce_lostpassword().
		if ( ! function_exists( 'login_header' ) ) {
			return;
		}
		$this->enforce_lostpassword( $errors );
	}

	/**
	 * The lost-password token check without the wp-login scoping — public so the
	 * pro plugin can apply it to WooCommerce / other-plugin lost-password forms
	 * (which fire the same lostpassword_post hook off the wp-login.php surface).
	 */
	public function enforce_lostpassword( $errors ) {
		if ( ! is_wp_error( $errors ) || ! $this->active() || ! $this->protects( 'lostpassword' ) ) {
			return;
		}
		if ( empty( $_POST ) || ! isset( $_POST['user_login'] ) ) {
			return;
		}
		if ( ! $this->token_passes() ) {
			$errors->add( 'qevix_shield_recaptcha', $this->fail_message() );
		}
	}

	/**
	 * One siteverify round-trip. Returns Google's decoded response array, or a
	 * WP_Error when Google could not be reached / answered unparseably.
	 */
	private function siteverify( $token, $secret ) {
		$response = wp_remote_post(
			self::VERIFY_URL,
			array(
				'timeout' => 10,
				'body'    => array(
					'secret'   => $secret,
					'response' => $token,
					'remoteip' => QevixShield_Util::get_client_ip(),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'qevix_shield_recaptcha_bad_response', __( 'Unreadable response from Google.', 'qevix-shield' ) );
		}
		return $data;
	}

	/** Login-time verdict: true = allow (incl. fail-open), false = block. */
	private function token_passes() {
		// v2 posts Google's own field from the checkbox widget; v3 posts ours.
		$field = 'v2' === $this->version() ? 'g-recaptcha-response' : self::FIELD;
		$token = isset( $_POST[ $field ] ) ? sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) : '';
		if ( '' === $token ) {
			// Must fail CLOSED: a stripped field and an unrendered widget look
			// identical here, so allowing an empty token would make reCAPTCHA
			// bypassable by just omitting it. The preflight + active()'s
			// is_verified() gate keep a mis-keyed config from reaching this line.
			return false;
		}

		$data = $this->siteverify( $token, $this->settings->get( 'recaptcha_secret_key' ) );

		if ( is_wp_error( $data ) ) {
			// Fail open on Google outage rather than locking every user out —
			// the free rate limiting / honeypot still apply underneath.
			return true;
		}

		if ( ! empty( $data['success'] ) ) {
			$score = isset( $data['score'] ) ? (float) $data['score'] : null;
			if ( null === $score || $score >= $this->threshold() ) {
				return true;
			}
			return $this->log_block( 'recaptcha_blocked' );
		}

		// A misconfigured site (bad secret, malformed request) fails every human
		// too, so fail open like an outage — but log it CRITICAL so the admin
		// hears about the silently unprotected form.
		$codes = isset( $data['error-codes'] ) ? (array) $data['error-codes'] : array();
		if ( array_intersect( $codes, self::CONFIG_ERRORS ) ) {
			QevixShield_Audit_Log::log(
				array(
					'action'   => 'recaptcha_misconfigured:' . implode( ',', array_map( 'sanitize_text_field', $codes ) ),
					'severity' => 'critical',
					'module'   => 'auth',
					'status'   => 'allowed',
				)
			);
			return true;
		}

		return $this->log_block( 'recaptcha_blocked' );
	}

	/** Logs a genuine reCAPTCHA rejection and returns false (block). */
	private function log_block( $action ) {
		QevixShield_Audit_Log::log(
			array(
				'action'   => $action,
				'severity' => 'warning',
				'module'   => 'auth',
				'status'   => 'blocked',
			)
		);
		return false;
	}

	private function fail_message() {
		return __( '<strong>Error</strong>: reCAPTCHA verification failed. Please try again.', 'qevix-shield' );
	}

	private function fail() {
		return new WP_Error( 'qevix_shield_recaptcha', $this->fail_message() );
	}

	/* -------------------- Settings page -------------------- */

	public function register_admin_pages( $pages ) {
		$pages[] = array(
			'slug'       => 'qevix-shield-recaptcha',
			'page_title' => __( 'Qevix Shield reCAPTCHA', 'qevix-shield' ),
			'menu_title' => __( 'reCAPTCHA', 'qevix-shield' ),
			'capability' => QevixShield_Settings::CAP,
			'callback'   => array( $this, 'render_settings_page' ),
			'tab'        => 'recaptcha',
			'position'   => 18,
		);
		return $pages;
	}

	/** Adds a reCAPTCHA tab to the shared Settings page. */
	public function register_settings_tabs( $tabs ) {
		$tabs[] = array(
			'slug'       => 'recaptcha',
			'label'      => __( 'reCAPTCHA', 'qevix-shield' ),
			'render'     => array( $this, 'render_section' ),
			'capability' => QevixShield_Settings::CAP,
			'position'   => 18,
		);
		return $tabs;
	}

	public function handle_save() {
		if ( ! current_user_can( QevixShield_Settings::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_recaptcha' );

		// "Protect Forms" — all three wp-login surfaces are available on every
		// tier (this plugin implements the render + verify for each). Login is
		// the floor: an empty selection falls back to it rather than silently
		// leaving the master switch on with nothing protected.
		$posted = isset( $_POST['recaptcha_forms'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['recaptcha_forms'] ) ) : array();
		$forms  = array_values( array_intersect( $posted, array( 'login', 'register', 'lostpassword' ) ) );
		if ( empty( $forms ) ) {
			$forms = array( 'login' );
		}

		$notices = array();

		// Site Key — reject a value that isn't a plausible reCAPTCHA key and
		// clear the field (not allowed). A saved-and-unchanged key re-submits its
		// own value, so a previously valid key just passes through.
		$siteKey = isset( $_POST['recaptcha_site_key'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['recaptcha_site_key'] ) ) ) : '';
		if ( '' !== $siteKey && ! self::looks_like_key( $siteKey ) ) {
			$notices[] = __( 'The Site Key was not saved — that is not a valid Google reCAPTCHA key (they start with 6L and are about 40 characters). The field has been cleared.', 'qevix-shield' );
			$siteKey   = '';
		}

		// Secret Key is write-only: only touch it when a new value is typed, and
		// reject an invalid one (keeping the previously saved secret untouched).
		$secretIn  = isset( $_POST['recaptcha_secret_key'] ) ? trim( (string) wp_unslash( $_POST['recaptcha_secret_key'] ) ) : '';
		$newSecret = null; // null = keep existing.
		if ( '' !== $secretIn ) {
			if ( self::looks_like_key( $secretIn ) ) {
				$newSecret = sanitize_text_field( $secretIn );
			} else {
				$notices[] = __( 'The Secret Key was not saved — that is not a valid Google reCAPTCHA key.', 'qevix-shield' );
			}
		}
		$effectiveSecret = ( null !== $newSecret ) ? $newSecret : (string) $this->settings->get( 'recaptcha_secret_key', '' );

		// "Turn on reCAPTCHA protection" is not allowed until BOTH a valid Site
		// Key and Secret Key are stored — otherwise it is left off (a wrong/empty
		// key with enforcement on would block every login).
		$enabled = ! empty( $_POST['recaptcha_enabled'] );
		if ( $enabled && ( '' === $siteKey || '' === trim( $effectiveSecret ) ) ) {
			$notices[] = __( 'reCAPTCHA was left OFF — it cannot be turned on until both a valid Site Key and Secret Key are saved.', 'qevix-shield' );
			$enabled   = false;
		}

		// ...and not until this exact trio has passed "Test keys". Read the
		// version from THIS request, not settings — the fingerprint has to
		// describe what is being saved, and the stored value is still the old
		// one at this point.
		$effectiveVersion = ( isset( $_POST['recaptcha_version'] ) && 'v3' === $_POST['recaptcha_version'] ) ? 'v3' : 'v2';

		if ( $enabled ) {
			$stored = (string) $this->settings->get( 'recaptcha_verified', '' );
			$want   = self::fingerprint( $siteKey, $effectiveVersion, $effectiveSecret );
			if ( '' === $stored || ! hash_equals( $stored, $want ) ) {
				$notices[] = __( 'reCAPTCHA was left OFF — these keys have not been tested yet. Press "Test keys" below to confirm they work on this site, then turn it on. This check exists because keys of the wrong type lock every user out of the login form, including you.', 'qevix-shield' );
				$enabled   = false;
			}
		}

		// Score threshold (v3 only). Clamped to Google's 0.0–1.0 range; anything
		// outside it falls back to the 0.5 default rather than being stored.
		$threshold = isset( $_POST['recaptcha_threshold'] ) ? (float) wp_unslash( $_POST['recaptcha_threshold'] ) : 0.5;
		if ( $threshold < 0 || $threshold > 1 ) {
			$threshold = 0.5;
		}

		$values = array(
			'recaptcha_enabled'        => $enabled,
			'recaptcha_site_key'       => $siteKey,
			'recaptcha_forms'          => $forms,
			'recaptcha_version'        => $effectiveVersion,
			'recaptcha_threshold'      => $threshold,
			'recaptcha_email_fallback' => ! empty( $_POST['recaptcha_email_fallback'] ),
		);
		if ( null !== $newSecret ) {
			$values['recaptcha_secret_key'] = $newSecret;
		}

		$this->settings->update( $values );

		/**
		 * Seam for a companion plugin to persist any reCAPTCHA settings of its
		 * OWN (e.g. coverage of forms this plugin does not implement). Every
		 * setting rendered by this plugin is saved above, on every tier —
		 * nothing here is licence-gated.
		 */
		do_action( 'qevix_shield_recaptcha_save_pro' );

		if ( ! empty( $notices ) ) {
			set_transient( 'qevix_shield_recaptcha_notice_' . get_current_user_id(), $notices, MINUTE_IN_SECONDS );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=qevix-shield-recaptcha&updated=true' ) );
		exit;
	}

	/** The form — shared by the standalone page and the Settings tab. */
	public function render_section() {
		$isPro      = (bool) apply_filters( 'qevix_shield_is_pro_active', false );
		$version    = $this->version();
		$threshold  = $this->threshold();
		$settings   = $this->settings;
		$isVerified = $this->is_verified();

		// One-shot validation notices from the last save (invalid key rejected /
		// enable blocked).
		$notices = get_transient( 'qevix_shield_recaptcha_notice_' . get_current_user_id() );
		delete_transient( 'qevix_shield_recaptcha_notice_' . get_current_user_id() );
		$notices = is_array( $notices ) ? $notices : array();

		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-recaptcha.php';
	}

	/** Submenu page: opens the shared tabbed Settings view on the reCAPTCHA tab. */
	public function render_settings_page() {
		QevixShield_Menu::render_tabbed_settings( 'recaptcha' );
	}
}
