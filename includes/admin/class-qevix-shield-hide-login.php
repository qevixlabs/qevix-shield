<?php
/**
 * Custom login URL: hides the real wp-login.php behind a configurable slug
 * and blocks/redirects direct hits on the default WP login/register/
 * lostpassword/resetpass/wp-admin endpoints (login/lostpassword/resetpass are
 * all wp-login.php with different ?action= params, so gating the one file
 * covers all of them; wp-register.php, wp-signup.php, a logged-out /wp-admin
 * hit, and the
 * /login, /login.php, /admin, /dashboard shorthand guesses core itself
 * recognizes are all gated separately below since none of them runs through
 * $pagenow==='wp-login.php').
 *
 * Technique: WP sets $pagenow from the actually-requested entry script
 * before 'init' fires, so a direct hit on wp-login.php can be told apart
 * from us internally `require`-ing it from within an /init/ callback that
 * was itself reached through index.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Hide_Login {

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	public function get_slug() {
		$slug = trim( (string) $this->settings->get( 'login_slug', 'login' ), " \t\n\r\0\x0B/" );
		return '' !== $slug ? $slug : 'login';
	}

	/**
	 * Login hiding is opt-in (default OFF): activating the plugin must never
	 * silently move the site's login URL. Both the URL rewriting and the
	 * request gating below bail when this is off, so wp-login.php keeps
	 * working exactly as stock until an admin enables the feature.
	 */
	private function enabled() {
		return (bool) $this->settings->get( 'hide_login_enabled', false );
	}

	/**
	 * Rewrites every core-generated login/logout/lostpassword/register URL
	 * (site_url()/network_site_url() with scheme login|login_post) so
	 * theme/core-rendered links point at the custom slug instead of
	 * wp-login.php.
	 */
	public function filter_login_url( $url, $path, $scheme ) {
		if ( ! $this->enabled() ) {
			return $url;
		}
		if ( ! in_array( $scheme, array( 'login', 'login_post' ), true ) ) {
			return $url;
		}
		if ( false === strpos( (string) $path, 'wp-login.php' ) ) {
			return $url;
		}
		return str_replace( 'wp-login.php', $this->get_slug(), $url );
	}

	/**
	 * Hooked on init: intercepts direct wp-login.php/wp-register.php/wp-admin
	 * hits and requests for the configured custom slug.
	 *
	 * wp-register.php no longer exists as a core file — core's own
	 * redirect_canonical() rewrites it to wp_registration_url(), which (like
	 * wp_login_url()) is already run through filter_login_url() and would
	 * hand an anonymous visitor a 301 straight to the "secret" slug. Same
	 * problem for a logged-out /wp-admin hit: core's auth_redirect() (called
	 * from wp-admin/admin.php, itself reached via this same init-firing
	 * bootstrap) builds its redirect target from wp_login_url() too. Both
	 * must be caught here, before core gets a chance to build that redirect,
	 * or the "hidden" slug leaks straight into a Location header.
	 */
	public function handle_request() {
		global $pagenow;

		if ( ! $this->enabled() ) {
			return;
		}

		// wp-signup.php is a real core file (unlike wp-register.php), so a
		// direct hit executes it with $pagenow === 'wp-signup.php' — and on a
		// non-multisite install it immediately 302s to wp_registration_url(),
		// which filter_login_url() has already rewritten to the secret slug.
		// Same leak shape as wp-register.php, but it must be caught by
		// $pagenow (also covers PATH_INFO hits like /wp-signup.php/x).
		if ( in_array( $pagenow, array( 'wp-login.php', 'wp-signup.php' ), true ) ) {
			$this->block_direct_access();
			return;
		}

		$requestPath = $this->get_request_path();

		// Suffix match, not exact match: core's own rewrite rule for this is
		// the wildcard `.*wp-register.php$` (registration_pages in
		// class-wp-rewrite.php) and redirect_canonical() matches on
		// basename() — so `/anything/wp-register.php` (no knowledge of the
		// real slug needed) reaches the same leaky redirect as a bare
		// `/wp-register.php` would. An exact-string check here would miss it.
		if ( str_ends_with( $requestPath, 'wp-register.php' ) || str_ends_with( $requestPath, 'wp-signup.php' ) ) {
			$this->block_direct_access();
			return;
		}

		if ( ! is_user_logged_in() && $this->is_direct_wp_admin_request() ) {
			$this->block_direct_access();
			return;
		}

		if ( $requestPath === $this->get_slug() ) {
			// wp-login.php is written for global scope, but we require it from
			// inside this method — so its top-level variables become locals here.
			// A fresh GET of the login form reads two variables that core only
			// assigns on POST/reset flows: $user_login (the username field value)
			// and $error (the deprecated wp_login() global). Seed them so core's
			// unconditional reads don't emit "Undefined variable" notices under
			// WP_DEBUG. wp-login.php overwrites $user_login on the flows that set it.
			$user_login = '';
			$error      = '';
			require ABSPATH . 'wp-login.php';
			exit;
		}

		// Reached only when $requestPath isn't the active slug, so any of
		// these guesses is by definition a guess, not the real thing — block
		// it the same as a direct wp-login.php hit. Otherwise core's own
		// wp_redirect_admin_locations() (template_redirect, priority 1000)
		// would 404-catch it and redirect straight to wp_login_url()/
		// admin_url(), which for wp_login_url() is the exact same filtered
		// target as everywhere else in this class — i.e. it would hand an
		// anonymous guesser the "secret" slug for free.
		if ( in_array( $requestPath, array( 'login', 'login.php', 'admin', 'dashboard' ), true ) ) {
			$this->block_direct_access();
			return;
		}
	}

	/**
	 * True for a browser-navigated wp-admin request — false for
	 * admin-ajax.php/admin-post.php, which must stay reachable while logged
	 * out (front-end AJAX, nopriv form posts).
	 *
	 * Two cases, both needed:
	 * 1. A real `/wp-admin/*.php` script actually executed (`is_admin()` /
	 *    `WP_ADMIN` true) — the normal case.
	 * 2. A *prefixed* guess like `/anything/wp-admin/` (or an Apache
	 *    PATH_INFO trick like `/index.php/anything/wp-admin/`). No real
	 *    wp-admin script ever runs for these — `get_request_path()` never
	 *    matches, `is_admin()` stays false — but core's own
	 *    `WP::parse_request()` (class-wp.php) has `if (
	 *    str_contains( $_SERVER['PHP_SELF'], 'wp-admin/' ) ) { unset(
	 *    $error ); unset( $perma_query_vars ); }`, a safety net that silently
	 *    clears any 404/permalink error whenever PHP_SELF contains
	 *    `wp-admin/` ANYWHERE, prefix or not — so instead of 404ing, the
	 *    request falls through to the default (home) query. We have to
	 *    catch this ourselves on `init`, before `parse_request()` runs,
	 *    using the same substring core's own bypass checks.
	 */
	private function is_direct_wp_admin_request() {
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
		if ( in_array( $script, array( 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return false;
		}

		if ( is_admin() ) {
			return true;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		return str_contains( $uri, 'wp-admin/' );
	}

	/**
	 * True when $url points at the page currently being served — the loop
	 * guard for 'custom' redirect mode. If an admin sets the custom URL to a
	 * location this handler itself blocks (e.g. /wp-admin), every hop of the
	 * resulting chain re-enters block_direct_access(); the chain terminates
	 * here by serving the 404 fallback instead of redirecting a page to
	 * itself.
	 */
	private function is_current_request( $url ) {
		$targetHost = wp_parse_url( $url, PHP_URL_HOST );
		$homeHost   = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( null !== $targetHost && strtolower( (string) $targetHost ) !== strtolower( (string) $homeHost ) ) {
			return false;
		}

		$uri         = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$currentPath = untrailingslashit( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$targetPath  = untrailingslashit( (string) wp_parse_url( $url, PHP_URL_PATH ) );

		return $currentPath === $targetPath;
	}

	private function get_request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		$homePath = (string) wp_parse_url( home_url(), PHP_URL_PATH );
		if ( '' !== $homePath && str_starts_with( $path, $homePath ) ) {
			$path = substr( $path, strlen( $homePath ) );
		}

		return trim( $path, '/' );
	}

	/**
	 * '404' mode deliberately does NOT render the theme's own 404.php via
	 * get_query_template(). Every caller of this method reaches it from
	 * 'init' — sometimes (the $pagenow==='wp-login.php' case) from *inside*
	 * wp-login.php's own script execution, which never runs through
	 * WP::main()/the 'wp'/'template_redirect' hooks at all. The theme's real
	 * 404.php depends on 'wp_enqueue_scripts' (block/global styles, the
	 * importmap script, the theme stylesheet) having already fired, which at
	 * this point in the request it has not — so including it here renders an
	 * unstyled, broken-looking page instead of a real 404. wp_die() is WP's
	 * own lifecycle-independent "terminate this request now" primitive and
	 * renders a consistent, readable page no matter how early it's called.
	 */
	private function block_direct_access() {
		$mode = $this->settings->get( 'redirect_mode', '404' );

		if ( 'home' === $mode ) {
			wp_safe_redirect( home_url() );
			exit;
		}

		if ( 'custom' === $mode ) {
			$customUrl = esc_url_raw( (string) $this->settings->get( 'redirect_custom_url', '' ) );
			// wp_safe_redirect() would be wrong here twice over: external hosts
			// are the point of this admin-configured setting, and for any host
			// not in allowed_redirect_hosts it silently swaps in its fallback,
			// admin_url() — sending the visitor to /wp-admin, which this very
			// handler blocks again → infinite redirect loop. wp_redirect() is
			// safe: the value only enters via the nonce+capability-protected
			// save handler and is esc_url_raw()'d.
			if ( '' !== $customUrl && ! $this->is_current_request( $customUrl ) ) {
				wp_redirect( $customUrl );
				exit;
			}
		}

		global $wp_query;
		$wp_query->set_404();
		nocache_headers();
		wp_die(
			esc_html__( 'Not Found', 'qevix-shield' ),
			esc_html__( '404 Not Found', 'qevix-shield' ),
			array( 'response' => 404 )
		);
	}
}
