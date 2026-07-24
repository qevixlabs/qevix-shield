<?php
/**
 * TOTP engine (RFC 6238) + Base32 + otpauth provisioning URI. Pure PHP, no
 * dependency. Compatible with Google Authenticator, Authy, 1Password,
 * Bitwarden, FreeOTP.
 *
 * Base TOTP is a free-tier feature: this engine lives in the free plugin so
 * two-factor authentication works with no pro license. The pro plugin reuses
 * this same class (it always runs with the free plugin present) rather than
 * shipping its own copy.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_TOTP {

	const PERIOD  = 30; // seconds per RFC 6238 default.
	const DIGITS  = 6;
	const WINDOW  = 1;  // accept the adjacent step each side for clock skew.

	private static $base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/** A fresh 160-bit secret, Base32-encoded (the standard authenticator length). */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * otpauth:// URI an authenticator app turns into a QR / manual entry.
	 * e.g. otpauth://totp/Site%20Name:user@example.com?secret=...&issuer=Site%20Name
	 */
	public static function provisioning_uri( $secret, $accountName, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $accountName );
		// RFC3986 encoding (%20, not +) so authenticator apps parse the issuer
		// correctly — the otpauth:// spec is percent-encoded, not form-encoded.
		$query = http_build_query(
			array(
				'secret' => $secret,
				'issuer' => $issuer,
				'digits' => self::DIGITS,
				'period' => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
		return 'otpauth://totp/' . $label . '?' . $query;
	}

	/** Verify a user-entered code against the secret, allowing ±WINDOW steps. */
	public static function verify( $secret, $code, $at = null ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$at        = null === $at ? time() : (int) $at;
		$counter   = (int) floor( $at / self::PERIOD );

		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			if ( hash_equals( self::code_at( $secret, $counter + $i ), $code ) ) {
				return true;
			}
		}
		return false;
	}

	private static function code_at( $secret, $counter ) {
		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return '';
		}

		$binary = pack( 'N*', 0 ) . pack( 'N*', $counter ); // 8-byte big-endian counter.
		$hash   = hash_hmac( 'sha1', $binary, $key, true );

		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$part   = substr( $hash, $offset, 4 );
		$value  = unpack( 'N', $part )[1] & 0x7FFFFFFF;

		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	public static function base32_encode( $data ) {
		if ( '' === $data ) {
			return '';
		}
		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::$base32[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( rtrim( (string) $b32, '=' ) );
		if ( '' === $b32 ) {
			return '';
		}
		$bits = '';
		$len  = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$pos = strpos( self::$base32, $b32[ $i ] );
			if ( false === $pos ) {
				return '';
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}
}
