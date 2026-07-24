<?php
/**
 * Small shared helpers used by the auth, logging, and alert modules.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Util {

	public static function get_client_ip() {
		$candidates = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );

		foreach ( $candidates as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) {
				continue;
			}
			$value = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
			$ip    = trim( explode( ',', $value )[0] );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '0.0.0.0';
	}

	public static function get_user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}

	/**
	 * Very small UA sniffing, good enough for the audit log's "browser"
	 * column. Not meant for feature detection.
	 */
	public static function get_browser_name( $userAgent ) {
		$ua = (string) $userAgent;

		$known = array(
			'Edg'     => 'Edge',
			'OPR'     => 'Opera',
			'Firefox' => 'Firefox',
			'Chrome'  => 'Chrome',
			'Safari'  => 'Safari',
			'MSIE'    => 'Internet Explorer',
			'Trident' => 'Internet Explorer',
		);

		foreach ( $known as $needle => $label ) {
			if ( false !== strpos( $ua, $needle ) ) {
				return $label;
			}
		}

		return '' === $ua ? '' : 'Unknown';
	}

	public static function ip_matches_whitelist( $ip, array $whitelist ) {
		foreach ( $whitelist as $entry ) {
			if ( $entry === $ip ) {
				return true;
			}
			if ( false !== strpos( $entry, '/' ) && self::ip_in_cidr( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	private static function ip_in_cidr( $ip, $cidr ) {
		if ( ! str_contains( $ip, '.' ) ) {
			return false; // CIDR matching here only supports IPv4; IPv6/CIDR is a PRO refinement.
		}

		list( $subnet, $maskBits ) = array_pad( explode( '/', $cidr ), 2, '32' );

		$ipLong     = ip2long( $ip );
		$subnetLong = ip2long( $subnet );
		if ( false === $ipLong || false === $subnetLong ) {
			return false;
		}

		$mask = -1 << ( 32 - (int) $maskBits );
		return ( $ipLong & $mask ) === ( $subnetLong & $mask );
	}

	/**
	 * Minimal, self-contained HTML email shell shared by BOTH plugins' mail
	 * (the pro plugin reuses this — free is always present when pro runs). Inline
	 * CSS is required for email — clients strip <style>/external CSS — so the
	 * admin "no inline styles" rule deliberately does NOT apply to emails.
	 * $inner is trusted HTML the caller has already escaped.
	 */
	public static function email_wrap( $heading, $inner ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s site name */
		$footer = sprintf( __( 'This is an automated security message from %s.', 'qevix-shield' ), $site );
		return '<div style="background:#f0f0f1;padding:24px 12px;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;">'
			. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">'
			. '<table role="presentation" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;">'
			. '<tr><td style="padding:0 4px 12px;color:#646970;font-size:13px;font-weight:600;letter-spacing:.3px;">' . esc_html( $site ) . '</td></tr>'
			. '<tr><td style="background:#ffffff;border:1px solid #dcdcde;border-radius:8px;padding:28px 24px;">'
			. '<h1 style="margin:0 0 14px;font-size:18px;line-height:1.3;color:#1d2327;">' . esc_html( $heading ) . '</h1>'
			. $inner
			. '</td></tr>'
			. '<tr><td style="padding:14px 4px 0;color:#8c8f94;font-size:12px;line-height:1.5;">' . esc_html( $footer ) . '</td></tr>'
			. '</table></td></tr></table></div>';
	}

	/**
	 * Send an HTML email with a plain-text alternative (AltBody), scoped to THIS
	 * message only: the content type + AltBody are set via a per-send
	 * phpmailer_init hook that is removed immediately, so wp_mail is never
	 * flipped globally for other plugins' mail (non-interference).
	 */
	public static function send_html_mail( $to, $subject, $html, $plaintext = '', array $headers = array() ) {
		$alt = null;
		if ( '' !== $plaintext ) {
			$alt = static function ( $phpmailer ) use ( $plaintext ) {
				$phpmailer->AltBody = $plaintext;
			};
			add_action( 'phpmailer_init', $alt );
		}
		$headers[] = 'Content-Type: text/html; charset=UTF-8';
		$sent      = wp_mail( $to, $subject, $html, $headers );
		if ( null !== $alt ) {
			remove_action( 'phpmailer_init', $alt );
		}
		return $sent;
	}
}
