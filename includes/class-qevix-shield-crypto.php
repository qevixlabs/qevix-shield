<?php
/**
 * At-rest encryption for sensitive config. The 2FA TOTP secret is the first
 * free-tier consumer (the free plugin deferred building this until a module
 * actually needed it — now one does).
 *
 * Key derivation: HKDF-SHA256 over the concatenated AUTH_KEY + SECURE_AUTH_KEY
 * salts from wp-config.php — never a hardcoded key. If those salts are ever
 * rotated, previously-encrypted values become undecryptable and the plugin
 * treats them as "not set" (e.g. a 2FA secret reads as no-2FA), which is the
 * safe direction to fail.
 *
 * Cipher: AES-256-GCM (authenticated encryption) so tampering with stored
 * ciphertext is detected on decrypt rather than yielding garbage plaintext.
 *
 * Deliberately independent of the pro plugin's QevixShield_Pro_Crypto (which
 * stays in pro for the license token). Same construction, disjoint HKDF info
 * string so ciphertext is not cross-decryptable between the two.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Crypto {

	const CIPHER = 'aes-256-gcm';

	private static function key() {
		$material = '';
		if ( defined( 'AUTH_KEY' ) ) {
			$material .= AUTH_KEY;
		}
		if ( defined( 'SECURE_AUTH_KEY' ) ) {
			$material .= SECURE_AUTH_KEY;
		}

		// Fallback so we never derive from an empty string on a misconfigured
		// install; still install-specific, just weaker.
		if ( '' === $material ) {
			$material = wp_salt( 'secure_auth' );
		}

		return hash_hkdf( 'sha256', $material, 32, 'qevix-shield-at-rest' );
	}

	/**
	 * @return string base64 of iv|tag|ciphertext, or '' on failure.
	 */
	public static function encrypt( $plaintext ) {
		$ivLen = openssl_cipher_iv_length( self::CIPHER );
		$iv    = random_bytes( $ivLen );
		$tag   = '';

		$ciphertext = openssl_encrypt( (string) $plaintext, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $ciphertext ) {
			return '';
		}

		return base64_encode( $iv . $tag . $ciphertext );
	}

	/**
	 * @return string|false plaintext, or false if missing/tampered/undecryptable.
	 */
	public static function decrypt( $stored ) {
		$raw = base64_decode( (string) $stored, true );
		if ( false === $raw ) {
			return false;
		}

		$ivLen  = openssl_cipher_iv_length( self::CIPHER );
		$tagLen = 16; // GCM tag.
		if ( strlen( $raw ) < $ivLen + $tagLen ) {
			return false;
		}

		$iv         = substr( $raw, 0, $ivLen );
		$tag        = substr( $raw, $ivLen, $tagLen );
		$ciphertext = substr( $raw, $ivLen + $tagLen );

		return openssl_decrypt( $ciphertext, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv, $tag );
	}
}
