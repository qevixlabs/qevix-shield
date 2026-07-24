<?php
/**
 * Honeypot field and IP whitelist (IP-only in the free tier).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Login_Protect {

	const HONEYPOT_FIELD = 'qevix_shield_hp_email';

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	public function render_honeypot_field() {
		if ( ! $this->settings->get( 'honeypot_enabled', true ) ) {
			return;
		}
		?>
		<p class="qevix-shield-hp-wrap" aria-hidden="true" style="position:absolute;left:-9999px;top:-9999px;">
			<label for="<?php echo esc_attr( self::HONEYPOT_FIELD ); ?>">Leave this field empty</label>
			<input type="text" name="<?php echo esc_attr( self::HONEYPOT_FIELD ); ?>" id="<?php echo esc_attr( self::HONEYPOT_FIELD ); ?>" value="" autocomplete="off" tabindex="-1" />
		</p>
		<?php
	}

	/** Hooked on `authenticate`; a filled honeypot short-circuits the login. */
	public function check_honeypot( $user ) {
		if ( ! $this->settings->get( 'honeypot_enabled', true ) ) {
			return $user;
		}

		if ( empty( $_POST[ self::HONEYPOT_FIELD ] ) ) {
			return $user;
		}

		QevixShield_Audit_Log::log(
			array(
				'action'   => 'honeypot_triggered',
				'severity' => 'warning',
				'module'   => 'auth',
				'status'   => 'blocked',
			)
		);

		// Generic error; never reveal that a honeypot was tripped.
		return new WP_Error( 'qevix_shield_honeypot', __( '<strong>Error</strong>: Invalid login attempt.', 'qevix-shield' ) );
	}

	/**
	 * Single source of truth for "is this IP exempt from blocking". Free
	 * contributes the IP/CIDR list below; pro ORs in CIDR ranges on top, so
	 * both the rate limiter and pro's blocking module see the same union
	 * answer.
	 */
	public function is_ip_whitelisted( $ip = null ) {
		$ip = $ip ?? QevixShield_Util::get_client_ip();
		return (bool) apply_filters( 'qevix_shield_ip_whitelisted', false, $ip );
	}

	/** Hooked on qevix_shield_ip_whitelisted: contributes the free IP/CIDR list. */
	public function filter_ip_whitelist( $matched, $ip ) {
		if ( $matched ) {
			return true;
		}
		return QevixShield_Util::ip_matches_whitelist( $ip, $this->settings->get_ip_whitelist() );
	}
}
