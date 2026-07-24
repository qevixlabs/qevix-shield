<?php
/**
 * Fixed-threshold login rate limiting + temporary IP lockout. Configurable
 * thresholds are a pro feature; the free tier reads the same setting keys
 * but only exposes non-editable fixed defaults in its own settings UI.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Rate_Limit {

	/** @var QevixShield_Settings */
	private $settings;

	/** @var QevixShield_Login_Protect */
	private $login_protect;

	public function __construct( QevixShield_Settings $settings, QevixShield_Login_Protect $loginProtect ) {
		$this->settings      = $settings;
		$this->login_protect = $loginProtect;
	}

	private function fails_key( $ip ) {
		return 'qevix_shield_fails_' . md5( $ip );
	}

	private function lockout_key( $ip ) {
		return 'qevix_shield_lockout_' . md5( $ip );
	}

	/** Whether brute-force rate limiting / lockout is switched on. Opt-in. */
	private function enabled() {
		return (bool) $this->settings->get( 'rate_limit_enabled', false );
	}

	/** Hooked on `authenticate` at priority 0, before WP checks credentials. */
	public function check_lockout( $user ) {
		if ( ! $this->enabled() ) {
			return $user;
		}

		$ip = QevixShield_Util::get_client_ip();

		if ( $this->login_protect->is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		if ( get_transient( $this->lockout_key( $ip ) ) ) {
			return new WP_Error( 'qevix_shield_locked_out', __( '<strong>Error</strong>: Too many failed login attempts. Please try again later.', 'qevix-shield' ) );
		}

		return $user;
	}

	public function on_login_failed( $username ) {
		if ( ! $this->enabled() ) {
			return;
		}

		$ip = QevixShield_Util::get_client_ip();

		if ( $this->login_protect->is_ip_whitelisted( $ip ) ) {
			return;
		}

		$key        = $this->fails_key( $ip );
		$windowSecs = max( 1, (int) $this->settings->get( 'rate_limit_window_minutes', 15 ) ) * MINUTE_IN_SECONDS;
		$threshold  = max( 1, (int) $this->settings->get( 'rate_limit_fails', 5 ) );

		$fails = (int) get_transient( $key );
		++$fails;
		set_transient( $key, $fails, $windowSecs );

		if ( $fails >= $threshold ) {
			$lockoutSecs = max( 1, (int) $this->settings->get( 'lockout_duration_minutes', 15 ) ) * MINUTE_IN_SECONDS;
			set_transient( $this->lockout_key( $ip ), true, $lockoutSecs );
			delete_transient( $key );

			QevixShield_Audit_Log::log(
				array(
					'action'   => 'ip_locked_out',
					'severity' => 'critical',
					'module'   => 'auth',
					'status'   => 'blocked',
					'username' => $username,
				)
			);
		}
	}

	public function on_login_success( $userLogin ) {
		delete_transient( $this->fails_key( QevixShield_Util::get_client_ip() ) );
	}
}
