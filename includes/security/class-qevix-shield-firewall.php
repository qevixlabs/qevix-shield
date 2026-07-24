<?php
/**
 * Firewall (FREE): signature-based request blocking for SQL injection, XSS,
 * LFI/RFI, directory traversal, command injection, and known bad bots.
 *
 * Timing: `run_early_check()` is called directly from the Qevix Shield
 * constructor — i.e. at plugin-include time, while wp-settings.php is still
 * loading plugins. That is the earliest a plugin can possibly act: before
 * other plugins load, before pluggable.php, before `init`. True
 * "before WordPress loads" filtering needs server-level config
 * (auto_prepend_file / a server WAF); the settings screen says so.
 *
 * Because pluggable.php has NOT loaded yet, nothing here may touch the
 * current user (no is_user_logged_in / current_user_can / wp_get_current_user)
 * and every audit-log call must pass an explicit user_id so the logger never
 * falls back to get_current_user_id().
 *
 * Scope: the request URI + query string are always inspected (raw and
 * double-percent-decoded); POST bodies only when `firewall_inspect_post` is
 * on. wp-admin requests are exempt (already behind authentication and the
 * hide-admin handling) EXCEPT admin-ajax.php / admin-post.php, which are
 * reachable logged-out and stay inspected. Whitelisted IPs are never blocked.
 *
 * Pro seams: `qevix_shield_firewall_signatures` (filter — category => pattern
 * list; pro can add XXE/SSRF/anomaly rules) and `qevix_shield_firewall_bad_bots`
 * (filter — user-agent substrings).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Firewall {

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Known scanner / attack-tool user-agent substrings (lowercase). Deliberately
	 * only tools, never generic HTTP libraries (python-requests, curl, …) that
	 * legitimate integrations use.
	 */
	const BAD_BOTS = array(
		'sqlmap',
		'havij',
		'nikto',
		'nessus',
		'openvas',
		'acunetix',
		'netsparker',
		'wpscan',
		'dirbuster',
		'gobuster',
		'ffuf',
		'wfuzz',
		'masscan',
		'zgrab',
		'joomscan',
		'fimap',
		'arachni',
		'w3af',
		'nuclei',
		'sqlninja',
		'libwww-perl',
	);

	/**
	 * Category => PCRE list, run case-insensitively against the raw and the
	 * double-decoded request URI/query (and, when enabled, the POST body).
	 * Patterns are deliberately conservative — classic attack shapes only —
	 * because a free-tier WAF's first duty is to not break the site.
	 *
	 * @return array<string, string[]>
	 */
	private function signatures() {
		$signatures = array(
			'sql_injection'     => array(
				'#union[\s/\*+]+(?:all[\s/\*+]+)?select#i',
				'#\binformation_schema\b#i',
				'#\b(?:sleep|benchmark)\s*\(\s*\d#i',
				'#\bload_file\s*\(#i',
				'#into\s+(?:out|dump)file#i',
				'#\bgroup_concat\s*\(#i',
				'#\b(?:or|and)\s+\d+\s*=\s*\d+\b#i',
				'#;\s*drop\s+table\b#i',
			),
			'xss'               => array(
				'#<script[\s>/]#i',
				'#javascript\s*:#i',
				'#\bon(?:error|load|mouseover|focus|pointerover|animationstart)\s*=#i',
				'#document\.cookie#i',
				'#<iframe[\s>/]#i',
				'#srcdoc\s*=#i',
				'#data:text/html#i',
			),
			'file_inclusion'    => array(
				'#\.\./#',
				'#\.\.\\\\#',
				'#/etc/passwd\b#i',
				'#proc/self/environ#i',
				'#php://(?:input|filter)#i',
				'#(?:expect|phar|zip|data)://#i',
				'#%00|\x00#',
			),
			'command_injection' => array(
				'#[;|`]\s*(?:cat|ls|id|whoami|wget|curl|bash|sh|nc|python|perl)\b#i',
				'#\$\(\s*(?:cat|wget|curl|id|whoami)\b#i',
				'#/bin/(?:ba|z|da)?sh\b#i',
				'#\b(?:wget|curl)\s+(?:-\S+\s+)*https?://#i',
				'#\bchmod\s+[0-7]{3,4}\b#i',
			),
		);

		return (array) apply_filters( 'qevix_shield_firewall_signatures', $signatures );
	}

	/** @return string[] */
	private function bad_bots() {
		$bots = (array) apply_filters( 'qevix_shield_firewall_bad_bots', self::BAD_BOTS );
		return array_filter( array_map( 'strtolower', array_map( 'strval', $bots ) ) );
	}

	/**
	 * Called directly at plugin-include time (see class docblock).
	 */
	public function run_early_check() {
		if ( ! $this->settings->get( 'firewall_enabled', true ) ) {
			return;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || in_array( PHP_SAPI, array( 'cli', 'phpdbg' ), true ) ) {
			return;
		}

		// IP whitelist, read straight from settings — the
		// qevix_shield_ip_whitelisted filter isn't populated this early.
		$ip = QevixShield_Util::get_client_ip();
		if ( QevixShield_Util::ip_matches_whitelist( $ip, $this->settings->get_ip_whitelist() ) ) {
			return;
		}

		// Bad bots first: cheapest check, and applies even to wp-admin paths
		// (a scanner UA has no business anywhere).
		if ( $this->settings->get( 'firewall_block_bad_bots', true ) ) {
			$ua = strtolower( QevixShield_Util::get_user_agent() );
			if ( '' !== $ua ) {
				foreach ( $this->bad_bots() as $bot ) {
					if ( false !== strpos( $ua, $bot ) ) {
						$this->block( 'bad_bot' );
					}
				}
			}
		}

		if ( $this->is_exempt_admin_request() ) {
			return;
		}

		$haystacks = $this->request_haystacks();
		foreach ( $this->signatures() as $category => $patterns ) {
			foreach ( (array) $patterns as $pattern ) {
				foreach ( $haystacks as $haystack ) {
					if ( '' !== $haystack && preg_match( $pattern, $haystack ) ) {
						$this->block( $category );
					}
				}
			}
		}

		if ( $this->is_rfi_attempt() ) {
			$this->block( 'remote_file_inclusion' );
		}
	}

	/**
	 * wp-admin requests are exempt from signature matching — they sit behind
	 * authentication (and the hide-admin block for logged-out hits), and admin
	 * screens legitimately move strings that look like attacks (log searches,
	 * post content). admin-ajax.php / admin-post.php stay inspected: both are
	 * reachable without authentication.
	 */
	private function is_exempt_admin_request() {
		$path = strtolower( rawurldecode( (string) wp_parse_url( $this->raw_uri(), PHP_URL_PATH ) ) );

		if ( ! str_contains( $path, 'wp-admin' ) && ! is_admin() ) {
			return false;
		}

		return ! in_array( basename( $path ), array( 'admin-ajax.php', 'admin-post.php' ), true );
	}

	private function raw_uri() {
		return isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
	}

	/**
	 * The strings the signatures run against: the raw URI+query (catches
	 * literal payloads and %00) and a double-percent-decoded copy (catches
	 * single- and double-encoded ones, e.g. %2527). POST bodies only when the
	 * inspect-post option is on — legitimate front-end content (comments,
	 * form plugins) can look attack-ish, so that's opt-in.
	 *
	 * @return string[]
	 */
	private function request_haystacks() {
		$raw = strtolower( $this->raw_uri() );

		$haystacks = array(
			$raw,
			rawurldecode( rawurldecode( $raw ) ),
		);

		if ( $this->settings->get( 'firewall_inspect_post', false )
			&& isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD']
			&& ! empty( $_POST ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WAF inspection, not form handling.
			$flat        = http_build_query( wp_unslash( $_POST ) );
			$haystacks[] = strtolower( rawurldecode( $flat ) );
		}

		return $haystacks;
	}

	/**
	 * RFI is detected structurally, not by regex: any GET parameter whose
	 * value is a URL on a FOREIGN host pointing at a PHP-ish file. Same-host
	 * URLs (redirect_to=…/wp-admin/post.php) are legitimate WP behavior.
	 */
	private function is_rfi_attempt() {
		if ( empty( $_GET ) ) {
			return false;
		}

		$homeHost = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$values   = array();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- WAF inspection, not form handling.
		array_walk_recursive( wp_unslash( $_GET ), function ( $value ) use ( &$values ) {
			if ( is_string( $value ) ) {
				$values[] = $value;
			}
		} );

		foreach ( $values as $value ) {
			$value = trim( $value );
			if ( ! preg_match( '#^(?:https?|ftps?)://#i', $value ) ) {
				continue;
			}
			$host = strtolower( (string) wp_parse_url( $value, PHP_URL_HOST ) );
			$path = (string) wp_parse_url( $value, PHP_URL_PATH );
			if ( '' !== $host && $host !== $homeHost && preg_match( '#\.ph(?:p\d?|tml|ar)$#i', $path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Log + terminate with 403. Severity is 'warning' (not 'critical') on
	 * purpose: internet background noise would otherwise turn the "critical
	 * always emails" guarantee into an inbox flood. user_id is pinned to 0 —
	 * pluggable.php hasn't loaded, the logger's get_current_user_id()
	 * fallback would fatal.
	 */
	private function block( $category ) {
		QevixShield_Audit_Log::log(
			array(
				'user_id'  => 0,
				'action'   => 'firewall_blocked:' . $category,
				'severity' => 'warning',
				'module'   => 'firewall',
				'status'   => 'blocked',
			)
		);

		nocache_headers();
		wp_die(
			esc_html__( 'Forbidden — this request was blocked by the site firewall.', 'qevix-shield' ),
			esc_html__( '403 Forbidden', 'qevix-shield' ),
			array( 'response' => 403 )
		);
	}
}
