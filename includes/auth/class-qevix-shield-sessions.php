<?php
/**
 * Session management — free tier.
 *
 * A user can view their own active sessions (browser, IP, login time,
 * last activity), and a password reset force-logs-out all of that
 * user's sessions (WP core's reset_password() calls wp_set_password()
 * directly, which does NOT destroy sessions — so we do it here).
 *
 * This class also owns the shared session data layer that the pro plugin
 * builds its admin session management on: the static read/write helpers
 * below talk to WordPress's default meta-based session store (`session_tokens`
 * user meta). If a site swaps in a custom session-token handler these degrade
 * gracefully (empty list / no-op) rather than fatal.
 *
 * "Last activity" is not tracked by WP core, so we attach a `last_active`
 * field at session creation and refresh it (throttled) on each page load.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Sessions {

	/** Don't rewrite last_active more than once per this many seconds. */
	const ACTIVITY_THROTTLE = 60;

	/* ------------------------------------------------------------------ */
	/* Data layer (shared with pro)                                        */
	/* ------------------------------------------------------------------ */

	/** SHA-256 verifier of the current request's session token, or ''. */
	public static function current_verifier() {
		$token = wp_get_session_token();
		return $token ? hash( 'sha256', $token ) : '';
	}

	/** Raw session map [verifier => session array] for a user. */
	public static function read_meta( $userId ) {
		$meta = get_user_meta( (int) $userId, 'session_tokens', true );
		return is_array( $meta ) ? $meta : array();
	}

	public static function write_meta( $userId, array $sessions ) {
		if ( empty( $sessions ) ) {
			delete_user_meta( (int) $userId, 'session_tokens' );
		} else {
			update_user_meta( (int) $userId, 'session_tokens', $sessions );
		}
	}

	/**
	 * Normalized, display-ready sessions for a user. Each row carries the
	 * verifier (so pro can target one for revocation) and an is_current flag.
	 */
	public static function get_user_sessions( $userId ) {
		$current = self::current_verifier();
		$rows    = array();
		$now     = time();

		foreach ( self::read_meta( $userId ) as $verifier => $session ) {
			// Skip already-expired tokens. WordPress prunes them only lazily
			// (on the next change to this user's sessions), so dead tokens can
			// linger in the meta long after they stop authenticating — listing
			// them makes one browser look like many live logins. WP's own
			// session API filters these out too; the current session is never
			// expired, so this can't hide the row the viewer is on.
			$expiration = isset( $session['expiration'] ) ? (int) $session['expiration'] : 0;
			if ( $expiration > 0 && $expiration < $now ) {
				continue;
			}

			$ua = isset( $session['ua'] ) ? (string) $session['ua'] : '';
			$ip = isset( $session['ip'] ) ? (string) $session['ip'] : '';
			$rows[] = array(
				'verifier'    => $verifier,
				'is_current'  => ( $verifier === $current && '' !== $current ),
				'ip'          => $ip,
				'browser'     => QevixShield_Util::get_browser_name( $ua ),
				'login'       => isset( $session['login'] ) ? (int) $session['login'] : 0,
				'last_active' => isset( $session['last_active'] ) ? (int) $session['last_active'] : ( isset( $session['login'] ) ? (int) $session['login'] : 0 ),
				'expiration'  => isset( $session['expiration'] ) ? (int) $session['expiration'] : 0,
			);
		}

		// Most-recently-active first.
		usort(
			$rows,
			static function ( $a, $b ) {
				return $b['last_active'] <=> $a['last_active'];
			}
		);

		return $rows;
	}

	/** Revoke a single session by verifier (used by pro's admin session UI). */
	public static function revoke( $userId, $verifier ) {
		$sessions = self::read_meta( $userId );
		if ( isset( $sessions[ $verifier ] ) ) {
			unset( $sessions[ $verifier ] );
			self::write_meta( $userId, $sessions );
			return true;
		}
		return false;
	}

	/** Destroy every session for a user. */
	public static function destroy_all_for_user( $userId ) {
		$manager = WP_Session_Tokens::get_instance( (int) $userId );
		$manager->destroy_all();
	}

	/* ------------------------------------------------------------------ */
	/* Last-activity tracking                                              */
	/* ------------------------------------------------------------------ */

	/** Hooked on attach_session_information: stamp a session at creation. */
	public function attach_session_information( $session, $userId ) {
		$session['last_active'] = time();
		return $session;
	}

	/** Hooked on init (priority 10): throttled refresh of last_active. */
	public function track_activity() {
		if ( ! is_user_logged_in() || wp_doing_ajax() || ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) ) {
			return;
		}

		$verifier = self::current_verifier();
		if ( '' === $verifier ) {
			return;
		}

		$userId   = get_current_user_id();
		$sessions = self::read_meta( $userId );
		if ( ! isset( $sessions[ $verifier ] ) ) {
			return;
		}

		$now  = time();
		$last = isset( $sessions[ $verifier ]['last_active'] ) ? (int) $sessions[ $verifier ]['last_active'] : 0;
		if ( ( $now - $last ) < self::ACTIVITY_THROTTLE ) {
			return;
		}

		$sessions[ $verifier ]['last_active'] = $now;
		self::write_meta( $userId, $sessions );
	}

	/* ------------------------------------------------------------------ */
	/* Force logout after password reset                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Hooked on after_password_reset. The user is not logged in at this point
	 * (they reset because they were locked out / forgot), so destroying all
	 * their sessions is safe and closes any hijacked session.
	 */
	public function force_logout_on_password_reset( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}
		self::destroy_all_for_user( $user->ID );

		QevixShield_Audit_Log::log(
			array(
				'action'   => 'sessions_force_logout',
				'severity' => 'warning',
				'module'   => 'auth',
				'status'   => 'success',
				'user_id'  => $user->ID,
				'username' => $user->user_login,
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Settings section (own sessions + pro injection seam)                */
	/* ------------------------------------------------------------------ */

	public function render_section() {
		// $sessions and $is_pro are read by the included view via shared include scope.
		$sessions = self::get_user_sessions( get_current_user_id() );
		$is_pro   = (bool) apply_filters( 'qevix_shield_is_pro_active', false );
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-sessions.php';
	}

	/* ------------------------------------------------------------------ */
	/* Self-service: log out my other sessions                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Hooked on admin_post_qevix_shield_logout_others. Any logged-in user may
	 * end all of THEIR OWN sessions except the current one — a one-click way to
	 * clear accumulated old logins. Uses core's `wp_destroy_other_sessions()`,
	 * which keeps the current request's token and drops the rest.
	 */
	public function handle_logout_others() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in to do this.', 'qevix-shield' ), 403 );
		}
		check_admin_referer( 'qevix_shield_logout_others' );

		wp_destroy_other_sessions();

		QevixShield_Audit_Log::log(
			array(
				'action'   => 'sessions_logout_others',
				'severity' => 'info',
				'module'   => 'auth',
				'status'   => 'success',
			)
		);

		wp_safe_redirect( add_query_arg(
			array( 'page' => 'qevix-shield-sessions', 'tab' => 'sessions', 'logged_out_others' => '1' ),
			admin_url( 'admin.php' )
		) );
		exit;
	}

	/** Shared formatter: a GMT unix timestamp as the site's local datetime. */
	public static function format_time( $timestamp ) {
		if ( ! $timestamp ) {
			return '—';
		}
		return wp_date( 'Y-m-d H:i', (int) $timestamp );
	}
}
