<?php
/**
 * Password policy enforcement: configurable minimum length, character-class
 * requirements, and disallowing the username/email as the password.
 *
 * Enforced everywhere a password is set: registration, profile/admin user
 * updates, and password reset. All three funnel through validate() so the
 * rules stay identical across flows.
 *
 * The pro plugin hooks the same three WordPress validation points to layer
 * on its own checks (common-password blocklist, history) —
 * it doesn't extend this class, the two stay decoupled through WP's error
 * objects.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Password_Policy {

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	/* ------------------------------------------------------------------ */
	/* Validation core                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Validate a candidate password against the configured policy.
	 *
	 * @param string $password  Raw candidate password.
	 * @param string $userLogin Username, checked against the disallow-user-info rule.
	 * @param string $userEmail Email, checked against the same rule.
	 * @return string[] List of human-readable error messages (empty = valid).
	 */
	public function validate( $password, $userLogin = '', $userEmail = '' ) {
		$errors = array();

		// Master switch: the whole free password rule set (length, character
		// classes, disallow username/email) applies only when enabled. Off by
		// default so a fresh install never rejects a password the admin didn't
		// opt into. Pro's own password features (expiry/history/common-password)
		// gate themselves separately.
		if ( ! $this->settings->get( 'pwd_policy_enabled', false ) ) {
			return $errors;
		}

		$password = (string) $password;

		$min = (int) $this->settings->get( 'pwd_min_length', 8 );
		if ( $min > 0 && strlen( $password ) < $min ) {
			/* translators: %d: minimum password length */
			$errors[] = sprintf( __( 'Password must be at least %d characters long.', 'qevix-shield' ), $min );
		}

		if ( $this->settings->get( 'pwd_require_upper', true ) && ! preg_match( '/[A-Z]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one uppercase letter.', 'qevix-shield' );
		}
		if ( $this->settings->get( 'pwd_require_lower', true ) && ! preg_match( '/[a-z]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one lowercase letter.', 'qevix-shield' );
		}
		if ( $this->settings->get( 'pwd_require_number', true ) && ! preg_match( '/[0-9]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one number.', 'qevix-shield' );
		}
		if ( $this->settings->get( 'pwd_require_special', false ) && ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one special character.', 'qevix-shield' );
		}

		// The password must not be, or contain, the username / email.
		if ( $this->settings->get( 'pwd_disallow_user_info', true ) && '' !== $password ) {
			$needles = array();
			if ( '' !== (string) $userLogin ) {
				$needles[] = strtolower( $userLogin );
			}
			if ( '' !== (string) $userEmail ) {
				$needles[] = strtolower( $userEmail );
				$local = strstr( $userEmail, '@', true );
				if ( false !== $local && '' !== $local ) {
					$needles[] = strtolower( $local );
				}
			}
			$haystack = strtolower( $password );
			foreach ( array_unique( array_filter( $needles ) ) as $needle ) {
				if ( strlen( $needle ) >= 3 && false !== strpos( $haystack, $needle ) ) {
					$errors[] = __( 'Password must not contain your username or email address.', 'qevix-shield' );
					break;
				}
			}
		}

		return $errors;
	}

	/* ------------------------------------------------------------------ */
	/* WordPress validation-hook adapters                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Hooked on `registration_errors`. The password (when the form collects one,
	 * e.g. WooCommerce / custom registration) lives in $_POST['pass1'].
	 */
	public function on_registration_errors( $errors, $sanitizedUserLogin = '', $userEmail = '' ) {
		$password = $this->posted_password();
		if ( '' === $password ) {
			return $errors; // Default WP registration emails a generated password; nothing to check.
		}
		$this->push_errors( $errors, $this->validate( $password, $sanitizedUserLogin, $userEmail ) );
		return $errors;
	}

	/**
	 * Hooked on `user_profile_update_errors` (profile.php + user-new.php).
	 *
	 * @param WP_Error         $errors Accumulating errors (by reference).
	 * @param bool             $update Whether this is an existing-user update.
	 * @param stdClass|WP_User $user   The user object being saved.
	 */
	public function on_profile_update_errors( $errors, $update, $user ) {
		$password = $this->posted_password();
		if ( '' === $password ) {
			return; // No password change submitted.
		}
		$login = isset( $user->user_login ) ? $user->user_login : '';
		$email = isset( $user->user_email ) ? $user->user_email : '';
		$this->push_errors( $errors, $this->validate( $password, $login, $email ) );
	}

	/**
	 * Hooked on `validate_password_reset`.
	 *
	 * @param WP_Error         $errors Accumulating errors (by reference).
	 * @param WP_User|WP_Error $user   The user resetting, or a WP_Error.
	 */
	public function on_validate_password_reset( $errors, $user ) {
		$password = $this->posted_password();
		if ( '' === $password ) {
			return;
		}
		$login = ( $user instanceof WP_User ) ? $user->user_login : '';
		$email = ( $user instanceof WP_User ) ? $user->user_email : '';
		$this->push_errors( $errors, $this->validate( $password, $login, $email ) );
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/** The raw candidate password from the current request, if any. */
	private function posted_password() {
		// Not a nonce-guarded action of ours — WP core validates the form nonce
		// before these hooks fire; we only read the value to validate it.
		return isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WP core validates the profile/registration nonce before this hook; value is only read to validate it.
	}

	/** Append a list of message strings onto a WP_Error under one code. */
	private function push_errors( $errors, array $messages ) {
		if ( ! ( $errors instanceof WP_Error ) ) {
			return;
		}
		foreach ( $messages as $message ) {
			$errors->add( 'qevix_shield_password_policy', $message );
		}
	}
}
