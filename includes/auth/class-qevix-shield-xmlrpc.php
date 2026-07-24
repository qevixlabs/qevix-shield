<?php
/**
 * XML-RPC protection: enforce a coarse mode (off / fully disabled / disable
 * pingbacks only) and log every XML-RPC request with its method name and
 * result.
 *
 * Enforcement and logging both funnel through is_blocked(), which seeds a
 * decision from the free mode and then runs the `qevix_shield_xmlrpc_method_blocked`
 * filter so the pro plugin (authenticated-only / method allowlist / trusted
 * IPs) can extend the same decision. Because logging and enforcement share
 * that one predicate, the audit log's "allowed/blocked" result always
 * matches what actually happened, whether or not pro is present.
 *
 * Blocking works by remapping every affected method (via the `xmlrpc_methods`
 * filter) to a callback that returns an IXR_Error fault, so a call to a blocked
 * method gets a clean XML-RPC error rather than executing.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_XMLRPC {

	/** Methods that operate without authentication (targeted by pingback/auth modes). */
	const ANON_METHODS = array(
		'pingback.ping',
		'pingback.extensions.getPingbacks',
		'demo.sayHello',
		'demo.addTwoNumbers',
	);

	const PINGBACK_METHODS = array(
		'pingback.ping',
		'pingback.extensions.getPingbacks',
	);

	/**
	 * IXR internal methods WordPress's IXR_Server registers AFTER the
	 * `xmlrpc_methods` filter, so filter_methods() can never remap them. They
	 * must be denied at the request level instead (see maybe_log_request) —
	 * otherwise `disabled` / allowlist / trusted-IP modes would still answer
	 * method enumeration and multicall even while claiming to block everything.
	 */
	const SYSTEM_METHODS = array(
		'system.listMethods',
		'system.getCapabilities',
		'system.multicall',
		'system.methodSignature',
		'system.methodHelp',
	);

	/** @var QevixShield_Settings */
	private $settings;

	/** @var bool Guards against logging the same request twice. */
	private $logged = false;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	private function mode() {
		return (string) $this->settings->get( 'xmlrpc_mode', 'off' );
	}

	/* ------------------------------------------------------------------ */
	/* Shared decision                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Is $method blocked for the current request? Seeds from the free mode and
	 * lets pro OR-in its own rules through the filter. The single source of
	 * truth for both enforcement and logging.
	 */
	public function is_blocked( $method, $ip = null ) {
		$ip     = ( null === $ip ) ? QevixShield_Util::get_client_ip() : $ip;
		$method = (string) $method;

		$blocked = false;
		switch ( $this->mode() ) {
			case 'disabled':
				$blocked = true;
				break;
			case 'pingbacks':
				$blocked = in_array( $method, self::PINGBACK_METHODS, true );
				break;
			case 'off':
			default:
				$blocked = false;
		}

		return (bool) apply_filters( 'qevix_shield_xmlrpc_method_blocked', $blocked, $method, $ip );
	}

	/* ------------------------------------------------------------------ */
	/* Enforcement                                                         */
	/* ------------------------------------------------------------------ */

	/** Hooked on `xmlrpc_enabled`: hard-off the auth methods when fully disabled. */
	public function filter_enabled( $enabled ) {
		return ( 'disabled' === $this->mode() ) ? false : $enabled;
	}

	/**
	 * Hooked on `xmlrpc_methods`: remap every blocked method to a deny callback
	 * returning an IXR_Error. Runs once per request when the server is built, so
	 * the IP/mode are already known.
	 */
	public function filter_methods( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		$ip = QevixShield_Util::get_client_ip();
		foreach ( array_keys( $methods ) as $name ) {
			if ( $this->is_blocked( $name, $ip ) ) {
				$methods[ $name ] = array( $this, 'deny' );
			}
		}
		return $methods;
	}

	/** Deny callback bound in place of a blocked method. */
	public function deny() {
		return new IXR_Error( 405, __( 'XML-RPC access to this method is blocked.', 'qevix-shield' ) );
	}

	/** Hooked on `wp_headers`: drop the X-Pingback advertisement when relevant. */
	public function filter_headers( $headers ) {
		if ( is_array( $headers ) && in_array( $this->mode(), array( 'disabled', 'pingbacks' ), true ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/* ------------------------------------------------------------------ */
	/* Logging                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Hooked on `init`. On an XML-RPC request, parse the top-level method
	 * name(s) from the raw request body and log each with its result. Runs
	 * before the server dispatches, and reading php://input here does not
	 * consume it for the server (text/xml bodies are re-readable).
	 */
	public function maybe_log_request() {
		if ( $this->logged ) {
			return;
		}
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}
		// NB: the xmlrpc_logging gate used to sit here; it moved down so the
		// system.* enforcement below runs regardless of whether request logging
		// is on (enforcement is not a logging feature).
		$this->logged = true;

		$raw = file_get_contents( 'php://input' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- raw request body; WP_Filesystem cannot read php://input.
		if ( ! is_string( $raw ) || '' === $raw ) {
			return;
		}

		if ( ! preg_match_all( '#<methodName>\s*([A-Za-z0-9_.]+)\s*</methodName>#', $raw, $m ) ) {
			return;
		}

		$ip      = QevixShield_Util::get_client_ip();
		$logging = (bool) $this->settings->get( 'xmlrpc_logging', true );

		// Enforce the IXR internal system.* methods that filter_methods() can't
		// reach (WordPress registers them AFTER the xmlrpc_methods filter). The
		// top-level method is the FIRST <methodName> ($m[1][0]); a multicall wraps
		// the rest after it. If that method is blocked for this request, deny the
		// WHOLE request here — before serve_request() runs — with the same IXR 405
		// fault filter_methods() returns. This is what makes `disabled` actually
		// disable the endpoint and stops allowlist / trusted-IP modes from leaking
		// method enumeration + multicall to callers they mean to block.
		$topLevel = (string) $m[1][0];
		if ( in_array( $topLevel, self::SYSTEM_METHODS, true ) && $this->is_blocked( $topLevel, $ip ) ) {
			if ( $logging ) {
				QevixShield_Audit_Log::log(
					array(
						'action'   => 'xmlrpc:' . $topLevel,
						'severity' => 'warning',
						'module'   => 'xmlrpc',
						'status'   => 'blocked',
					)
				);
			}
			$this->deny_request();
		}

		// Log every method (allowed or blocked) when request logging is on.
		if ( ! $logging ) {
			return;
		}
		foreach ( array_unique( $m[1] ) as $method ) {
			$blocked = $this->is_blocked( $method, $ip );
			QevixShield_Audit_Log::log(
				array(
					'action'   => 'xmlrpc:' . $method,
					'severity' => $blocked ? 'warning' : 'info',
					'module'   => 'xmlrpc',
					'status'   => $blocked ? 'blocked' : 'allowed',
				)
			);
		}
	}

	/**
	 * Emit the same IXR 405 "blocked" fault filter_methods() returns and
	 * terminate, for the request-level system.* denial above. Runs on `init`,
	 * before the XML-RPC server dispatches; the IXR classes aren't loaded yet,
	 * so the fault XML is written by hand rather than via IXR_Error.
	 */
	private function deny_request() {
		if ( ! headers_sent() ) {
			status_header( 405 );
			header( 'Content-Type: text/xml; charset=' . get_option( 'blog_charset', 'UTF-8' ) );
		}
		nocache_headers();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
		echo "<methodResponse>\n  <fault>\n    <value>\n      <struct>\n";
		echo "        <member><name>faultCode</name><value><int>405</int></value></member>\n";
		echo '        <member><name>faultString</name><value><string>' . esc_html__( 'XML-RPC access to this method is blocked.', 'qevix-shield' ) . "</string></value></member>\n";
		echo "      </struct>\n    </value>\n  </fault>\n</methodResponse>";
		exit;
	}
}
