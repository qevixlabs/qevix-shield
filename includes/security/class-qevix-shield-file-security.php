<?php
/**
 * File Security (FREE): block web requests for sensitive project/VCS files
 * that must never be exposed (.env, .git, composer.json, package.json, …),
 * plus the direct-access hardening toggles: direct-PHP-access blocking for
 * plugins/themes/wp-includes, directory-listing denial, readme/changelog/
 * license (enumeration-metadata) blocking, and PHP-execution denial in
 * uploads/cache/backups/logs.
 *
 * Enforcement is two-layered:
 *
 * 1. PHP-level on `init` at priority 0 (just before the hide-login handler
 *    at 1): any request that reaches WordPress and matches a rule is
 *    terminated. Sensitive/meta files get a 404 — the match is by name only
 *    (no filesystem check), so the response can't be used as an oracle for
 *    whether the file exists. Direct-PHP / PHP-exec / directory requests get
 *    a 403 — those paths are structural, not existence probes.
 *
 * 2. Server-level via managed .htaccess rules (Apache/LiteSpeed only,
 *    detected via $is_apache): a `# BEGIN Qevix Shield` marker block in the
 *    root .htaccess plus drop-in .htaccess files in the PHP-exec-denied
 *    directories, synced on every File Security save
 *    (`qevix_shield_sync_server_rules` action) and removed on deactivation/
 *    uninstall. This is the layer that covers what PHP never sees: existing
 *    static files (a real readme.txt), existing .php files executed directly
 *    by the server, and actual directory-index listings. On nginx there is
 *    no .htaccess; the settings screen shows the equivalent server-block
 *    snippet to paste instead of pretending otherwise.
 *
 * The blocklist is extensible via `qevix_shield_sensitive_files` (filter) —
 * exact names, or `*`-prefixed suffix patterns like `*.sql` (pro's
 * backup/dump blocking + custom entries use both) — without this class
 * changing; `qevix_shield_server_rules` (filter) lets pro extend the root
 * .htaccess block. The settings view uses the single-form pattern
 * (`qevix_shield_file_security_pro_values` filter + free's save handler firing
 * `qevix_shield_file_security_save_pro`); the old
 * `qevix_shield_file_security_pro_fields` render-injection action is gone.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_File_Security {

	/**
	 * Files (and the .git/.svn directories) that must never be exposed over
	 * the web. Lowercase; matching is case-insensitive.
	 */
	/**
	 * Suffix patterns added when Block Backup & Dump Files is on. All are
	 * `*`-prefixed for the suffix matcher below (`*.sql` also covers
	 * db-backup.sql at any depth). Deliberately no bare archive types
	 * (.zip/.tar) — too much legitimate content ships as a plain archive;
	 * .tgz/.tar.gz/.wpress are backup-shaped enough to block.
	 */
	const BACKUP_SUFFIXES = array(
		'*.sql',
		'*.sql.gz',
		'*.bak',
		'*.old',
		'*.orig',
		'*.bkp',
		'*.swp',
		'*.tgz',
		'*.tar.gz',
		'*.wpress',
	);

	const SENSITIVE_FILES = array(
		'.env',
		'.git',
		'.svn',
		'.gitignore',
		'.htaccess',
		'.htpasswd',
		'.user.ini',
		'wp-config.php',
		'debug.log',
		'error_log',
		'composer.json',
		'composer.lock',
		'package.json',
		'package-lock.json',
		'yarn.lock',
		'docker-compose.yml',
		'phpunit.xml',
		'readme.md',
		'changelog.md',
	);

	/**
	 * Plugin/theme enumeration metadata: the files scanners request to
	 * fingerprint installed plugins and their versions. Separate toggle from
	 * SENSITIVE_FILES because a site may legitimately want its own
	 * readme.html reachable.
	 */
	const META_FILES = array(
		'readme.txt',
		'readme.html',
		'changelog.txt',
		'license.txt',
		'licence.txt',
		'license.md',
	);

	/**
	 * wp-content subdirectories that must never execute PHP (relative names,
	 * used in both the PHP-level regex and the .htaccess drop-in targets).
	 */
	const PHP_EXEC_DIRS = array( 'uploads', 'cache', 'upgrade', 'backup', 'backups', 'log', 'logs' );

	/** PHP-ish extensions, shared by the direct-PHP and PHP-exec matchers. */
	const PHP_EXT_PATTERN = '\.ph(?:p\d?|tml|ar)';

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	public function is_enabled() {
		return (bool) $this->settings->get( 'block_sensitive_files', true );
	}

	/**
	 * The effective 404-blocklist: the free constant, the meta files when
	 * that toggle is on, plus whatever pro (or site code) adds through the
	 * filter, normalized to lowercase.
	 *
	 * @return string[]
	 */
	public function get_blocked_names() {
		$names = self::SENSITIVE_FILES;
		if ( $this->settings->get( 'fs_block_meta_files', true ) ) {
			$names = array_merge( $names, self::META_FILES );
		}
		if ( (bool) $this->settings->get( 'fs_block_backups', false ) ) {
			$names = array_merge( $names, self::BACKUP_SUFFIXES );
		}
		$names = array_merge( $names, $this->custom_entries() );
		$names = (array) apply_filters( 'qevix_shield_sensitive_files', $names );
		$names = array_filter( array_map( 'strtolower', array_map( 'strval', $names ) ) );
		return array_values( array_unique( $names ) );
	}

	/**
	 * Hooked on `init` priority 0: run every enabled PHP-level rule against
	 * the request path. Order: name-based 404 rules first (no oracle), then
	 * the structural 403 rules.
	 */
	/**
	 * Master switch for the whole File Security tab (files + hardening + firewall
	 * live under it). While off, no request enforcement runs here and the managed
	 * server rules are emitted empty so a save retracts them.
	 */
	public function master_enabled() {
		return (bool) $this->settings->get( 'file_security_enabled', false );
	}

	public function handle_request() {
		if ( ! $this->master_enabled() ) {
			return;
		}

		$path = $this->get_request_path();
		if ( '' === $path ) {
			return;
		}

		if ( $this->is_enabled() ) {
			$match = $this->match_sensitive_name( $path );
			if ( null !== $match ) {
				$this->log_block( 'sensitive_file_blocked:' . $match );
				$this->block_404();
			}
		}

		if ( $this->settings->get( 'fs_block_direct_php', true )
			&& preg_match( '#/(?:wp-content/(?:plugins|themes)|wp-includes)/.+' . self::PHP_EXT_PATTERN . '(?:$|/)#', $path ) ) {
			$this->log_block( 'direct_php_blocked' );
			$this->block_403();
		}

		if ( $this->settings->get( 'fs_disable_php_exec', true )
			&& preg_match( '#/wp-content/(?:' . implode( '|', self::PHP_EXEC_DIRS ) . ')/.*' . self::PHP_EXT_PATTERN . '(?:$|/)#', $path ) ) {
			$this->log_block( 'php_execution_blocked' );
			$this->block_403();
		}

		if ( $this->settings->get( 'fs_disable_dir_listing', true ) && $this->is_directory_browse( $path ) ) {
			$this->log_block( 'directory_listing_blocked' );
			$this->block_403();
		}
	}

	/**
	 * Decoded, lowercased request path. The raw REQUEST_URI is percent-decoded
	 * before splitting so an encoded probe (%2eenv) matches the same as a
	 * plain one.
	 */
	private function get_request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		return strtolower( rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) ) );
	}

	/**
	 * Returns the blocked name the path matches, or null. Matching by segment
	 * covers files at any depth (/sub/dir/.env) and everything inside a
	 * blocked directory (/.git/config, /.git/HEAD).
	 *
	 * Blocklist entries starting with `*` are suffix patterns: `*.sql`
	 * matches any segment ending in ".sql" (used by the backup/dump blocking and
	 * these through the `qevix_shield_sensitive_files` filter; exact names
	 * can't cover db-backup.sql, site.tar.gz, …). Path and entries are both
	 * lowercase by this point.
	 *
	 * @return string|null
	 */
	private function match_sensitive_name( $path ) {
		$names    = array();
		$suffixes = array();
		foreach ( $this->get_blocked_names() as $entry ) {
			if ( 0 === strpos( $entry, '*' ) ) {
				if ( strlen( $entry ) > 1 ) {
					$suffixes[] = substr( $entry, 1 );
				}
			} else {
				$names[] = $entry;
			}
		}

		foreach ( explode( '/', $path ) as $segment ) {
			if ( '' === $segment ) {
				continue;
			}
			if ( in_array( $segment, $names, true ) ) {
				return $segment;
			}
			foreach ( $suffixes as $suffix ) {
				if ( str_ends_with( $segment, $suffix ) ) {
					return $segment;
				}
			}
		}
		return null;
	}

	/**
	 * A "browse" request: any extensionless path under wp-content or
	 * wp-includes (real assets there always carry an extension; nothing
	 * routes pretty URLs under those trees), e.g. /wp-content/plugins/ or
	 * /wp-content/uploads/2026/07.
	 */
	private function is_directory_browse( $path ) {
		if ( ! preg_match( '#/(?:wp-content|wp-includes)(?:/|$)#', $path ) ) {
			return false;
		}
		$basename = basename( rtrim( $path, '/' ) );
		return false === strpos( $basename, '.' );
	}

	private function log_block( $action ) {
		QevixShield_Audit_Log::log(
			array(
				'action'   => $action,
				'severity' => 'warning',
				'module'   => 'file_security',
				'status'   => 'blocked',
			)
		);
	}

	/**
	 * Same lifecycle-independent 404 as QevixShield_Hide_Login: we're on
	 * `init`, long before `template_redirect`, so the theme's 404.php would
	 * render unstyled — wp_die() is the reliable early-termination primitive.
	 */
	private function block_404() {
		global $wp_query;
		$wp_query->set_404();
		nocache_headers();
		wp_die(
			esc_html__( 'Not Found', 'qevix-shield' ),
			esc_html__( '404 Not Found', 'qevix-shield' ),
			array( 'response' => 404 )
		);
	}

	private function block_403() {
		nocache_headers();
		wp_die(
			esc_html__( 'Forbidden', 'qevix-shield' ),
			esc_html__( '403 Forbidden', 'qevix-shield' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Admin-defined extra protected files (one per line or comma-separated):
	 * an exact filename, or a `*.suffix` pattern handled by the same matcher
	 * as SENSITIVE_FILES. A bare `*` is ignored — it would block everything.
	 *
	 * @return string[]
	 */
	private function custom_entries() {
		$raw     = (string) $this->settings->get( 'fs_custom_blocklist', '' );
		$entries = array();
		foreach ( (array) preg_split( '/[\r\n,]+/', $raw ) as $entry ) {
			$entry = strtolower( trim( (string) $entry ) );
			if ( '' === $entry || '*' === rtrim( $entry, '.' ) ) {
				continue;
			}
			$entries[] = $entry;
		}
		return array_values( array_unique( $entries ) );
	}

	/**
	 * Server-rule fragments for the backup/dump suffixes and the admin's custom
	 * blocklist, in whichever syntax the caller needs. Kept in one place so the
	 * Apache and nginx builders can never drift apart.
	 *
	 * @param string $flavour 'apache' or 'nginx'.
	 * @return string[]
	 */
	private function extra_blocklist_rules( $flavour ) {
		$rules  = array();
		$apache = ( 'apache' === $flavour );

		if ( (bool) $this->settings->get( 'fs_block_backups', false ) ) {
			$exts = array();
			foreach ( self::BACKUP_SUFFIXES as $suffix ) {
				$exts[] = preg_quote( ltrim( substr( $suffix, 1 ), '.' ), '#' );
			}
			$rules[] = $apache
				? 'RewriteRule \\.(?:' . implode( '|', $exts ) . ')$ - [R=404,L,NC]'
				: 'location ~* \\.(?:' . implode( '|', $exts ) . ')$ { return 404; }';
		}

		foreach ( $this->custom_entries() as $entry ) {
			if ( 0 === strpos( $entry, '*' ) ) {
				$pat     = preg_quote( substr( $entry, 1 ), '#' );
				$rules[] = $apache
					? 'RewriteRule ' . $pat . '$ - [R=404,L,NC]'
					: 'location ~* ' . $pat . '$ { return 404; }';
			} else {
				$pat     = preg_quote( $entry, '#' );
				$rules[] = $apache
					? 'RewriteRule (?:^|/)' . $pat . '(?:/|$) - [R=404,L,NC]'
					: 'location ~* (?:^|/)' . $pat . '(?:/|$) { return 404; }';
			}
		}

		return $rules;
	}

	/* ---------------------------------------------------------------------
	 * Server-level rules (.htaccess) — Apache/LiteSpeed only.
	 * ------------------------------------------------------------------- */

	/** WP sets $is_apache from SERVER_SOFTWARE for both Apache and LiteSpeed. */
	public static function server_supports_htaccess() {
		global $is_apache;
		return ! empty( $is_apache );
	}

	/**
	 * Hooked on `qevix_shield_sync_server_rules` (fired after a File Security
	 * save): rewrite the root marker block and the per-directory drop-ins to
	 * match the current toggles. Admin-only context, so the wp-admin include
	 * guards are cheap insurance rather than a real load.
	 */
	public function sync_server_rules() {
		if ( ! self::server_supports_htaccess() ) {
			return;
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		insert_with_markers( get_home_path() . '.htaccess', 'QevixShield', $this->root_htaccess_lines() );

		// Master off (or the sub-toggle off) → write empty drop-ins, retracting
		// any PHP-deny rules previously placed in the upload/cache/etc. dirs.
		$deny = ( $this->master_enabled() && $this->settings->get( 'fs_disable_php_exec', true ) ) ? self::php_deny_lines() : array();
		foreach ( self::php_exec_dir_paths() as $dir ) {
			if ( is_dir( $dir ) ) {
				insert_with_markers( trailingslashit( $dir ) . '.htaccess', 'QevixShield', $deny );
			}
		}
	}

	/**
	 * Root .htaccess marker-block content, built from the toggles. Filterable
	 * (`qevix_shield_server_rules`) so pro can extend it.
	 *
	 * @return string[]
	 */
	private function root_htaccess_lines() {
		$lines = array();

		// Master off → no managed rules, so sync_server_rules writes an empty
		// marker block (i.e. removes the previous rules) rather than leaving the
		// server enforcing what the PHP layer no longer does.
		if ( ! $this->master_enabled() ) {
			return $lines;
		}

		if ( $this->settings->get( 'fs_disable_dir_listing', true ) ) {
			$lines[] = 'Options -Indexes';
		}

		if ( $this->settings->get( 'hide_server_headers', true ) ) {
			$lines[] = 'ServerSignature Off';
			$lines[] = '<IfModule mod_headers.c>';
			$lines[] = 'Header always unset X-Powered-By';
			$lines[] = 'Header always unset X-Pingback';
			$lines[] = '</IfModule>';
		}

		$rewrites = array();
		if ( $this->is_enabled() ) {
			// Dotfiles (.env, .git/, .svn/, .htaccess, …) except .well-known (ACME).
			$rewrites[] = 'RewriteRule (?:^|/)\.(?!well-known(?:/|$)) - [R=404,L,NC]';
			$rewrites[] = 'RewriteRule (?:^|/)(?:composer\.(?:json|lock)|package(?:-lock)?\.json|yarn\.lock|docker-compose\.yml|phpunit\.xml|wp-config\.php|debug\.log|error_log|readme\.md|changelog\.md)$ - [R=404,L,NC]';
			$rewrites = array_merge( $rewrites, $this->extra_blocklist_rules( 'apache' ) );
		}
		if ( $this->settings->get( 'fs_block_meta_files', true ) ) {
			$rewrites[] = 'RewriteRule (?:^|/)(?:readme\.(?:txt|html)|changelog\.txt|licen[sc]e\.txt|license\.md)$ - [R=404,L,NC]';
		}
		if ( $this->settings->get( 'fs_block_direct_php', true ) ) {
			$rewrites[] = 'RewriteRule ^wp-content/(?:plugins|themes)/.+' . self::PHP_EXT_PATTERN . '$ - [F,L,NC]';
			$rewrites[] = 'RewriteRule ^wp-includes/.+' . self::PHP_EXT_PATTERN . '$ - [F,L,NC]';
		}
		if ( $this->settings->get( 'fs_disable_php_exec', true ) ) {
			$rewrites[] = 'RewriteRule ^wp-content/(?:' . implode( '|', self::PHP_EXEC_DIRS ) . ')/.+' . self::PHP_EXT_PATTERN . '$ - [F,L,NC]';
		}
		if ( $rewrites ) {
			$lines[] = '<IfModule mod_rewrite.c>';
			$lines[] = 'RewriteEngine On';
			$lines   = array_merge( $lines, $rewrites );
			$lines[] = '</IfModule>';
		}

		return (array) apply_filters( 'qevix_shield_server_rules', $lines );
	}

	/**
	 * Drop-in content for the PHP-exec-denied directories (Apache 2.4 syntax
	 * with a 2.2 fallback).
	 *
	 * @return string[]
	 */
	public static function php_deny_lines() {
		return array(
			'<FilesMatch "' . self::PHP_EXT_PATTERN . '$">',
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
			'</FilesMatch>',
		);
	}

	/**
	 * Absolute paths of the directories that get a PHP-deny drop-in. Uploads
	 * comes from wp_get_upload_dir() (it can live outside wp-content); the
	 * rest are conventional wp-content subdirectories.
	 *
	 * @return string[]
	 */
	public static function php_exec_dir_paths() {
		$paths  = array();
		$upload = wp_get_upload_dir();
		if ( ! empty( $upload['basedir'] ) ) {
			$paths[] = $upload['basedir'];
		}
		foreach ( self::PHP_EXEC_DIRS as $dir ) {
			if ( 'uploads' !== $dir ) {
				$paths[] = WP_CONTENT_DIR . '/' . $dir;
			}
		}
		return array_values( array_unique( $paths ) );
	}

	/**
	 * Strip every Qevix Shield marker block (root + drop-ins). Called from the
	 * deactivator and uninstall.php — static so neither needs a settings
	 * instance, and it removes the whole block including the BEGIN/END
	 * markers rather than leaving an empty pair behind.
	 */
	public static function remove_server_rules() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		$files = array( get_home_path() . '.htaccess' );
		foreach ( self::php_exec_dir_paths() as $dir ) {
			$files[] = trailingslashit( $dir ) . '.htaccess';
		}

		foreach ( $files as $file ) {
			if ( ! is_file( $file ) || ! wp_is_writable( $file ) ) {
				continue;
			}
			$contents = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading our own marker block out of a local .htaccess; runs on deactivate/uninstall where WP_Filesystem credentials may not be obtainable, and failing to retract the rules would leave the site enforcing them after the plugin is gone.
			if ( false === strpos( $contents, '# BEGIN Qevix Shield' ) ) {
				continue;
			}
			$stripped = preg_replace( '/\s*# BEGIN Qevix Shield.*?# END Qevix Shield\s*/s', "\n", $contents );
			if ( null === $stripped ) {
				continue;
			}
			if ( '' === trim( $stripped ) ) {
				wp_delete_file( $file ); // Drop-in we created is now empty — remove it entirely.
			} else {
				file_put_contents( $file, $stripped ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- writing back the same local .htaccess minus our marker block; see the read above for why WP_Filesystem is not used on this path.
			}
		}
	}

	/**
	 * The nginx equivalent of the managed .htaccess rules, shown on the settings
	 * screen when the server isn't Apache (a plugin can't write nginx config, so
	 * the admin pastes this once).
	 *
	 * Built from the SAME toggle state as root_htaccess_lines(), so it reflects
	 * exactly the options the admin has enabled above — not a fixed catch-all —
	 * and is run through the `qevix_shield_nginx_rules` filter so pro contributes
	 * its backup/dump + custom-blocklist location rules, mirroring how pro
	 * extends the Apache block via `qevix_shield_server_rules`. Instance (not
	 * static) because it reads live settings; the File Security view has
	 * $file_security in scope.
	 *
	 * @return string
	 */
	public function nginx_snippet() {
		$lines = array( '# Qevix Shield — add inside your server { } block (nginx ignores .htaccess)' );

		// Master off → nothing to add; the tab is inert until File Security is on.
		if ( ! $this->master_enabled() ) {
			$lines[] = '# (File Security is currently disabled — no rules to add.)';
			return implode( "\n", $lines );
		}

		if ( $this->settings->get( 'fs_disable_dir_listing', true ) ) {
			$lines[] = 'autoindex off;';
		}
		if ( $this->settings->get( 'hide_server_headers', true ) ) {
			$lines[] = 'server_tokens off;';
		}
		if ( $this->is_enabled() ) {
			// Dotfiles (.env, .git/, .htaccess, …) except .well-known (ACME).
			$lines[] = 'location ~* (?:^|/)\.(?!well-known(?:/|$)) { return 404; }';
			$lines[] = 'location ~* (?:^|/)(?:composer\.(?:json|lock)|package(?:-lock)?\.json|yarn\.lock|docker-compose\.yml|phpunit\.xml|wp-config\.php|debug\.log|error_log|readme\.md|changelog\.md)$ { return 404; }';
			$lines = array_merge( $lines, $this->extra_blocklist_rules( 'nginx' ) );
		}
		if ( $this->settings->get( 'fs_block_meta_files', true ) ) {
			$lines[] = 'location ~* (?:^|/)(?:readme\.(?:txt|html)|changelog\.txt|licen[sc]e\.txt|license\.md)$ { return 404; }';
		}
		if ( $this->settings->get( 'fs_block_direct_php', true ) ) {
			$lines[] = 'location ~* ^/(?:wp-content/(?:plugins|themes)|wp-includes)/.+\.ph(?:p\d?|tml|ar)$ { deny all; }';
		}
		if ( $this->settings->get( 'fs_disable_php_exec', true ) ) {
			$lines[] = 'location ~* ^/wp-content/(?:' . implode( '|', self::PHP_EXEC_DIRS ) . ')/.+\.ph(?:p\d?|tml|ar)$ { deny all; }';
		}

		/**
		 * nginx counterpart of `qevix_shield_server_rules`: pro appends its
		 * backup/dump + custom-blocklist `location` directives here so an nginx
		 * site's pasted snippet covers the same files the Apache block does.
		 *
		 * @param string[] $lines nginx directive lines.
		 */
		$lines = (array) apply_filters( 'qevix_shield_nginx_rules', $lines );

		return implode( "\n", $lines );
	}

	/** Settings-tab render callback (File Security tab + submenu). */
	public function render_section() {
		$settings      = $this->settings;
		$file_security = $this;
		include QEVIX_SHIELD_PLUGIN_DIR . 'includes/admin/views/settings-file-security.php';
	}
}
