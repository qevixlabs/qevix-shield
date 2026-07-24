<?php
/**
 * Shared "is this an interactive login form POST?" detector.
 *
 * WooCommerce is not the only plugin with its own front-end login surface —
 * Ultimate Member, Easy Digital Downloads, MemberPress, Paid Memberships Pro,
 * Restrict Content Pro, Theme My Login, WP-Members, Profile Builder,
 * BuddyPress/BuddyBoss, bbPress, LearnDash/LifterLMS/Tutor LMS, and the
 * Elementor Pro / WPForms / Gravity Forms login widgets all render their own
 * form and end up calling wp_signon()/wp_authenticate() with the submitted
 * credentials. Enumerating each plugin's POST signature would be an endless
 * allowlist, so detection is GENERIC instead:
 *
 *   A login is "interactive" when the exact password being authenticated
 *   arrived in the request's form body ($_POST). A human filling a form is
 *   the only party that does that — programmatic wp_signon() calls carry
 *   credentials in code, REST/application-password auth carries them in
 *   headers, and OAuth/social-login handshakes have no password at all.
 *
 * Used by 2FA (challenge every interactive login, whatever plugin's form it
 * came through). reCAPTCHA deliberately does NOT use it: enforcing a token on
 * a form where no token field was rendered would lock users out, so its
 * coverage stays an explicit per-form allowlist + filter.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Login_Context {

	/**
	 * True when the credentials being authenticated came from a login form a
	 * human just submitted (any plugin's form), false for programmatic and
	 * non-renderable contexts.
	 *
	 * Non-interactive by definition: WP-CLI, cron, AJAX, REST, XML-RPC — even
	 * if a plugin logs in over admin-ajax, an HTML challenge can't render
	 * inside that response. Those keep the documented pass-through behavior
	 * (2FA never fatals a programmatic sign-in) rather than failing closed.
	 *
	 * @param string $username Username as handed to the authenticate filter.
	 * @param string $password Plaintext password as handed to the filter.
	 * @return bool
	 */
	public static function is_interactive_login_post( $username = '', $password = '' ) {
		$interactive = self::detect( (string) $password );

		/**
		 * Lets an integration override the detection: return true to force the
		 * 2FA challenge onto a login flow the heuristic misses, false to exempt
		 * one (e.g. a custom form that must stay challenge-free).
		 *
		 * @param bool   $interactive Detected value.
		 * @param string $username    Username being authenticated.
		 */
		return (bool) apply_filters( 'qevix_shield_interactive_login_post', $interactive, (string) $username );
	}

	private static function detect( $password ) {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || in_array( PHP_SAPI, array( 'cli', 'phpdbg' ), true ) ) {
			return false;
		}
		if ( wp_doing_cron() || wp_doing_ajax() ) {
			return false;
		}
		if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return false;
		}

		// wp-login.php itself (covers every ?action= view, and the hide-login
		// slug that internally require()s it).
		if ( function_exists( 'login_header' ) ) {
			return true;
		}

		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] || empty( $_POST ) ) {
			return false;
		}

		// WooCommerce my-account/checkout login: recognized explicitly (the
		// one integration we ship dedicated redirect handling for).
		if ( class_exists( 'WooCommerce' ) && isset( $_POST['login'], $_POST['username'], $_POST['password'] ) ) {
			return true;
		}

		// Generic: the submitted password appears verbatim in the form body.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- detection only; each caller's own flow enforces its nonces.
		return '' !== $password && self::post_contains_value( wp_unslash( $_POST ), $password );
	}

	/** Depth-limited search for an exact string among the POST values. */
	private static function post_contains_value( $data, $needle, $depth = 0 ) {
		if ( $depth > 3 ) {
			return false;
		}
		foreach ( (array) $data as $value ) {
			if ( is_array( $value ) ) {
				if ( self::post_contains_value( $value, $needle, $depth + 1 ) ) {
					return true;
				}
			} elseif ( is_string( $value ) && $value === $needle ) {
				return true;
			}
		}
		return false;
	}
}
