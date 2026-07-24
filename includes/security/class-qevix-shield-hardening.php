<?php
/**
 * Information-disclosure hardening (FREE): hide the WordPress version, hide /
 * restrict the REST API, block author + user enumeration, strip identifying
 * response headers, and suppress on-screen error output.
 *
 * Everything is a toggle on the File Security tab. Honest-scope notes:
 * - The `Server:` response header is written by the web server itself after
 *   PHP finishes — no plugin can remove it. We remove what PHP controls
 *   (X-Powered-By, X-Pingback) and the UI says the rest is server config.
 * - Error display: wp_debug_mode() runs its ini_set() calls before plugins
 *   load, so our later ini_set('display_errors', 0) wins even when
 *   WP_DEBUG_DISPLAY is true. Errors keep going to the PHP error log /
 *   debug.log (which File Security's sensitive-file blocklist covers) —
 *   hidden from visitors, still logged internally.
 * - Author enumeration: only the `?author=N` ID→username oracle is blocked
 *   (404, per spec) plus the users sitemap; pretty author archives a theme
 *   links to on purpose stay working.
 * - User enumeration: /wp/v2/users* REST routes are removed for logged-OUT
 *   requests only, so the block editor's author dropdown and /users/me keep
 *   working for authenticated users.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Hardening {

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	private function on( $key ) {
		return (bool) $this->settings->get( $key, true );
	}

	/**
	 * Called directly at plugin-include time (not hooked): the whole point is
	 * to flip display_errors off before any later code can emit a notice.
	 *
	 * Scope is deliberately narrow: only `display_errors` is touched, and only
	 * to turn on-screen error output OFF (the documented "Hide Error Messages"
	 * feature). We do NOT force `log_errors` on or alter `display_startup_errors`
	 * — those are the host's global logging policy to set, not ours, and forcing
	 * them site-wide could push a site past its host's limits.
	 */
	public function suppress_error_display() {
		if ( ! $this->on( 'hide_php_errors' ) ) {
			return;
		}
		@ini_set( 'display_errors', '0' ); // phpcs:ignore WordPress.PHP.IniSet, WordPress.PHP.NoSilencedErrors -- suppresses on-screen PHP errors at runtime when the admin opts in; @ tolerates hosts where ini_set is disabled.
	}

	/**
	 * Hooked on `init`: de-register the head/header actions the toggles cover
	 * and drop headers PHP controls. Runs early (priority 1) so it beats
	 * anything that sends output.
	 */
	public function apply_hardening() {
		if ( $this->on( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( $this->settings->get( 'hide_rest_api', false ) ) {
			remove_action( 'wp_head', 'rest_output_link_wp_head' );
			remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
			remove_action( 'template_redirect', 'rest_output_link_header', 11 );
		}

		if ( $this->on( 'hide_server_headers' ) ) {
			remove_action( 'wp_head', 'rsd_link' );
			if ( ! headers_sent() ) {
				header_remove( 'X-Powered-By' );
				header_remove( 'Server' ); // No-op behind nginx/Apache (they append it after PHP), but harmless.
			}
		}

		if ( $this->on( 'hide_php_errors' ) ) {
			global $wpdb;
			$wpdb->hide_errors();
		}
	}

	/**
	 * script_loader_src / style_loader_src: strip `?ver=` ONLY when it equals
	 * the core version (style.css?ver=6.9 is the leak). Plugin/theme versions
	 * are left alone so their cache busting keeps working.
	 */
	public function strip_version_query( $src ) {
		if ( ! $this->on( 'hide_wp_version' ) || ! is_string( $src ) || '' === $src ) {
			return $src;
		}

		global $wp_version;
		$query = (string) wp_parse_url( $src, PHP_URL_QUERY );
		if ( '' === $query ) {
			return $src;
		}
		parse_str( $query, $args );
		if ( isset( $args['ver'] ) && $args['ver'] === $wp_version ) {
			$src = remove_query_arg( 'ver', $src );
		}

		return $src;
	}

	/**
	 * rest_authentication_errors: when Hide REST API is on, unauthenticated
	 * REST requests get a 401 instead of data. Existing errors/results pass
	 * through untouched.
	 */
	public function require_rest_auth( $result ) {
		if ( ! $this->settings->get( 'hide_rest_api', false ) ) {
			return $result;
		}
		if ( null !== $result || is_user_logged_in() ) {
			return $result;
		}

		return new WP_Error(
			'rest_login_required',
			__( 'The REST API on this site is restricted to authenticated users.', 'qevix-shield' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * rest_endpoints: drop the /wp/v2/users routes for logged-out requests
	 * (wp-json/wp/v2/users is the classic username-harvesting endpoint).
	 */
	public function filter_rest_endpoints( $endpoints ) {
		if ( ! $this->on( 'block_user_enum' ) || is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	/**
	 * wp_sitemaps_add_provider: the users sitemap is the same username leak
	 * as ?author=N, so it rides the same toggle. Returning a non-provider
	 * makes core skip registration.
	 */
	public function filter_sitemap_provider( $provider, $name ) {
		if ( 'users' === $name && $this->on( 'block_author_enum' ) ) {
			return false;
		}
		return $provider;
	}

	/**
	 * Hooked on `init` (before redirect_canonical can turn ?author=N into
	 * /author/username/): 404 any front-end author-ID probe from anyone who
	 * couldn't read the user list anyway.
	 */
	public function block_author_enumeration() {
		if ( ! $this->on( 'block_author_enum' ) || is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only probe detection.
		if ( ! isset( $_GET['author'] ) ) {
			return;
		}
		if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
			return;
		}

		QevixShield_Audit_Log::log(
			array(
				'action'   => 'author_enumeration_blocked',
				'severity' => 'warning',
				'module'   => 'hardening',
				'status'   => 'blocked',
			)
		);

		// Same lifecycle-independent 404 as QevixShield_File_Security::block():
		// too early for the theme's 404.php to render styled.
		global $wp_query;
		$wp_query->set_404();
		nocache_headers();
		wp_die(
			esc_html__( 'Not Found', 'qevix-shield' ),
			esc_html__( '404 Not Found', 'qevix-shield' ),
			array( 'response' => 404 )
		);
	}

	/**
	 * wp_headers filter: drop X-Pingback regardless of the XML-RPC module's
	 * mode (that module only strips it in its blocking modes).
	 */
	public function filter_wp_headers( $headers ) {
		if ( $this->on( 'hide_server_headers' ) && isset( $headers['X-Pingback'] ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}
}
