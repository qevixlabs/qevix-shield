<?php
/**
 * File Security settings section (form only — no page chrome; used by the
 * Settings > File Security tab). Expects $settings and $file_security.
 *
 * Free owns the base toggles here (sensitive files, direct-access hardening,
 * information disclosure, firewall). The pro "Advanced File Security" fields
 * (backup/SQL-dump blocking, custom protected patterns) render in the SAME
 * form — single-form pattern like Login Protection: unlicensed shows the
 * upsell card instead of the fields; licensed non-admins get them read-only
 * in a disabled fieldset; values come from
 * `qevix_shield_file_security_pro_values` and free's save handler fires
 * `qevix_shield_file_security_save_pro` so pro persists them from $_POST.
 * (The old `qevix_shield_file_security_pro_fields` render-injection action is
 * gone.)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$blockedNames = $file_security->get_blocked_names();
$isApache     = QevixShield_File_Security::server_supports_htaccess();


?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'qevix_shield_save_settings' ); ?>
	<input type="hidden" name="action" value="qevix_shield_save_settings" />
	<input type="hidden" name="qevix_shield_tab" value="file-security" />

	<?php $fileSecurityOn = (bool) $settings->get( 'file_security_enabled', false ); ?>
	<h3><?php esc_html_e( 'File Security', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Prevent development and configuration files from being exposed over the web, harden information disclosure, and run the request firewall.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Enable File Security', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Master switch for this entire tab — the file blocks, the hardening options, and the firewall all below. While OFF, none of them act, so you can configure everything first and switch it on when ready. Turn it ON to activate whatever you have enabled below.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="file_security_enabled" value="1" <?php checked( $fileSecurityOn ); ?> /> <?php esc_html_e( 'Enable file security, hardening and firewall (everything below acts only when this is on)', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default — none of the protections below are active until you enable this.', 'qevix-shield' ); ?></p>
				<?php
				if ( ! $fileSecurityOn ) {
					QevixShield_Menu::dependency_notice( __( 'File Security is <strong>off</strong> — every option below is saved as a draft and does nothing until you turn this on.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Sensitive Files', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Attackers probe URLs like <code>yoursite.com/.env</code> or <code>/wp-config.php</code> hoping to read database passwords and API keys. This blocks every request naming one of the protected files (list below). Leave on unless a specific tool of yours genuinely needs one of them over the web.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="block_sensitive_files" value="1" <?php checked( $settings->get( 'block_sensitive_files', true ) ); ?> /> <?php esc_html_e( 'Return a 404 for any request that targets a sensitive file', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Blocked requests are recorded in the audit log. A 404 (not a 403) is returned so probes cannot tell whether the file exists.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Meta Files', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Example: fetching <code>/wp-content/plugins/some-plugin/readme.txt</code> tells an attacker you run that plugin and its exact version — enough to pick a matching exploit. Blocking these files makes that fingerprinting fail without affecting normal visitors.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="fs_block_meta_files" value="1" <?php checked( $settings->get( 'fs_block_meta_files', true ) ); ?> /> <?php esc_html_e( 'Return a 404 for readme.txt, readme.html, changelog.txt, license.txt and similar files', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Scanners request these files to enumerate installed plugins and themes and read their exact versions.', 'qevix-shield' ); ?></p>
				<?php
				if ( $settings->get( 'fs_block_meta_files', false ) && ! $settings->get( 'block_sensitive_files', false ) ) {
					QevixShield_Menu::dependency_notice( __( 'This rides on <strong>Block Sensitive Files</strong>, which is off above — so meta files are not blocked yet. Turn on Block Sensitive Files for this to take effect.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Protected Files', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'The current blocklist, shown for reference — it follows the two toggles above (and Pro additions) automatically; there is nothing to type here.', 'qevix-shield' ) ); ?>
				<p class="qevix-shield-code-list">
					<?php foreach ( $blockedNames as $blockedName ) : ?>
						<code><?php echo esc_html( $blockedName ); ?></code>
					<?php endforeach; ?>
				</p>
				<p class="description"><?php esc_html_e( 'Matched anywhere in the URL path, case-insensitively — including inside subdirectories and everything within a blocked directory such as .git.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'Extra Protected Files', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Additions to the blocklist above: backup and database-dump extensions, plus your own protected-file patterns.', 'qevix-shield' ); ?></p>

	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Backup &amp; Dump Files', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Forgotten copies like <code>backup.sql</code>, <code>wp-config.php.bak</code> or <code>site.tar.gz</code> hand an attacker your whole database or configuration in one download. This 404s any request for a file ending in a backup/dump extension, wherever it sits.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="fs_block_backups" value="1" <?php checked( (bool) $settings->get( 'fs_block_backups', false ) ); ?> /> <?php esc_html_e( 'Return a 404 for backup and database-dump files (.sql, .sql.gz, .bak, .old, .orig, .bkp, .swp, .tgz, .tar.gz, .wpress)', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Matched by file extension anywhere in the site, on top of the blocklist above.', 'qevix-shield' ); ?></p>
				<?php
				if ( (bool) $settings->get( 'fs_block_backups', false ) && ! $settings->get( 'block_sensitive_files', false ) ) {
					QevixShield_Menu::dependency_notice( __( 'This rides on <strong>Block Sensitive Files</strong>, which is off above — backup and dump files are not blocked yet. Turn on Block Sensitive Files for this to take effect.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="fs_custom_blocklist"><?php esc_html_e( 'Custom Protected Files', 'qevix-shield' ); ?></label></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Your own additions to the blocklist, one per line. An exact name (<code>secrets.txt</code>) blocks that file or directory anywhere in the site; a pattern starting with <code>*</code> (<code>*.log</code>) blocks anything ending that way. Everything gets the same stealth 404.', 'qevix-shield' ) ); ?>
				<textarea id="fs_custom_blocklist" name="fs_custom_blocklist" rows="4" class="large-text" placeholder="secrets.txt&#10;*.log"><?php echo esc_textarea( (string) $settings->get( 'fs_custom_blocklist', '' ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'One entry per line: an exact file/directory name, or *.extension for a suffix match. Added to the Protected Files list above.', 'qevix-shield' ); ?></p>
				<?php
				if ( '' !== trim( (string) $settings->get( 'fs_custom_blocklist', '' ) ) && ! $settings->get( 'block_sensitive_files', false ) ) {
					QevixShield_Menu::dependency_notice( __( 'These entries ride on <strong>Block Sensitive Files</strong>, which is off above — they are not blocked yet. Turn on Block Sensitive Files for them to take effect.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'Direct Access Protection', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Stop PHP files and folder listings from being served directly by URL, outside WordPress.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Direct PHP Access', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Example: requesting <code>/wp-content/plugins/foo/helper.php</code> directly runs that file outside WordPress — a favourite way to trigger vulnerable plugin code or reveal errors. Blocked with a 403; WordPress itself loading those files is unaffected.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="fs_block_direct_php" value="1" <?php checked( $settings->get( 'fs_block_direct_php', true ) ); ?> /> <?php esc_html_e( 'Return a 403 for direct requests to PHP files inside wp-content/plugins, wp-content/themes and wp-includes', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Plugin and theme PHP files are meant to run only when WordPress loads them — never when requested directly by URL.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Disable PHP Execution', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Uploads/cache/backup folders should only ever hold images and documents, never runnable code. If malware sneaks a <code>shell.php</code> into <code>wp-content/uploads/</code>, this stops it from ever executing — turning a site takeover into a harmless dead file.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="fs_disable_php_exec" value="1" <?php checked( $settings->get( 'fs_disable_php_exec', true ) ); ?> /> <?php esc_html_e( 'Deny .php / .phtml / .phar execution inside uploads, cache, upgrade, backups and logs', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Even if malware manages to upload a shell.php into these directories, it cannot be executed.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Disable Directory Listing', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Without this, visiting a folder URL like <code>/wp-content/uploads/2026/</code> can show a browsable index of every file inside — private uploads, backups, plugin names. Blocking it keeps folder contents invisible; direct links to individual files keep working.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="fs_disable_dir_listing" value="1" <?php checked( $settings->get( 'fs_disable_dir_listing', true ) ); ?> /> <?php esc_html_e( 'Return a 403 for directory browse requests such as /wp-content/uploads/ or /wp-content/plugins/', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Adds Options -Indexes on Apache and blocks extensionless wp-content / wp-includes paths that reach WordPress.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Web Server Rules', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'PHP-level blocking only sees requests that reach WordPress; files the web server hands out directly (an existing readme.txt, a real .php file) need rules in the server itself. On Apache/LiteSpeed those rules are written for you on Save; on nginx copy the shown snippet into your server config once. Either way the snippet/block mirrors exactly the options you have ticked above (plus any Pro backup/custom rules).', 'qevix-shield' ) ); ?>
				<?php if ( $isApache ) : ?>
					<p class="description"><?php esc_html_e( 'Apache/LiteSpeed detected: matching .htaccess rules are written automatically when you save this tab (a managed "# BEGIN Qevix Shield" block in the root .htaccess plus drop-in files in the protected directories), and removed when the plugin is deactivated. These server-level rules also cover files that exist on disk and are served without WordPress running.', 'qevix-shield' ); ?></p>
				<?php else : ?>
					<p class="description"><?php esc_html_e( 'This server is not Apache/LiteSpeed, so .htaccess rules have no effect here. The PHP-level blocking above applies to every request that reaches WordPress; for files the web server serves directly (existing readme.txt files, direct hits on existing .php files, real directory indexes), add the equivalent rules to your server configuration:', 'qevix-shield' ); ?></p>
					<textarea readonly rows="8" class="large-text code" onclick="this.select();"><?php echo esc_textarea( $file_security->nginx_snippet() ); ?></textarea>
					<p class="description">
						<span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
						<?php esc_html_e( 'This snippet mirrors the options you have enabled above — including your backup-file and custom-blocklist rules. If you change any File Security setting, re-copy it into your nginx config. Paste it inside the site\'s server { } block and reload nginx; a syntax error there can take the whole site down, so test with "nginx -t" first.', 'qevix-shield' ); ?>
					</p>
				<?php endif; ?>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'Information Disclosure', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Remove the version numbers, headers, and endpoints attackers use to fingerprint your site.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Hide WordPress Version', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Your page source normally announces <code>&lt;meta name="generator" content="WordPress 7.0"&gt;</code> and tags assets with <code>?ver=7.0</code>. Scanners use that to match your site against version-specific exploits. This removes both traces; keeping WordPress updated is still the real fix.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="hide_wp_version" value="1" <?php checked( $settings->get( 'hide_wp_version', true ) ); ?> /> <?php esc_html_e( 'Remove the generator meta tag and strip ?ver= query strings that expose the core version', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Only version strings equal to the WordPress core version are stripped — plugin and theme cache-busting keeps working.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Hide REST API', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Requires login for everything under <code>/wp-json/</code>. Strong privacy, but it breaks anything that reads your site anonymously — contact-form submissions from some plugins, mobile apps, embeds of your posts on other sites. Turn on only if you know nothing public uses your REST API.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="hide_rest_api" value="1" <?php checked( $settings->get( 'hide_rest_api', false ) ); ?> /> <?php esc_html_e( 'Require authentication for all /wp-json/ requests and remove REST discovery links', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default: front-end plugins that call the REST API anonymously (contact forms, oEmbed consumers, mobile apps) will stop working while this is on.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Author Enumeration', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Example attack: requesting <code>yoursite.com/?author=1</code> normally redirects to <code>/author/admin/</code> — revealing the login username for user #1, then #2, #3… With this on, those probes get a 404 and usernames stay secret. Author links your theme prints keep working.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="block_author_enum" value="1" <?php checked( $settings->get( 'block_author_enum', true ) ); ?> /> <?php esc_html_e( 'Return a 404 for ?author=N probes instead of redirecting to /author/username/', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Also removes the users sitemap. Regular author archive links used by your theme keep working.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Block User Enumeration', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'The same username-harvesting trick via the REST API: <code>/wp-json/wp/v2/users</code> lists all account names to anyone. This hides that endpoint from logged-out visitors only — the block editor and profile screens, which need it while logged in, are untouched.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="block_user_enum" value="1" <?php checked( $settings->get( 'block_user_enum', true ) ); ?> /> <?php esc_html_e( 'Remove the /wp-json/wp/v2/users endpoints for visitors who are not logged in', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Logged-in users keep the endpoints, so the block editor and profile screens are unaffected.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Hide Server Headers', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Every response normally carries headers like <code>X-Powered-By: PHP/8.0</code> that tell attackers your exact software stack. This strips what PHP controls. The <code>Server:</code> header is added by the web server itself and can only be hidden in server config.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="hide_server_headers" value="1" <?php checked( $settings->get( 'hide_server_headers', true ) ); ?> /> <?php esc_html_e( 'Remove the X-Powered-By and X-Pingback headers and the RSD discovery link', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'The "Server:" header itself is added by the web server after PHP finishes and cannot be removed by a plugin — hide it in the server configuration (Apache: ServerTokens Prod; nginx: server_tokens off).', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Hide Error Messages', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'A raw PHP or database error on screen can leak file paths, table names, even query fragments — a map of your site\'s internals. Visitors see nothing; the full detail still lands in the server\'s error log for you to debug with.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="hide_php_errors" value="1" <?php checked( $settings->get( 'hide_php_errors', true ) ); ?> /> <?php esc_html_e( 'Suppress on-screen PHP and database error output', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Errors are still written to the PHP error log / debug.log (which the sensitive-file blocklist protects from web access) — hidden from visitors, logged internally.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'Firewall', 'qevix-shield' ); ?></h3>
	<p class="description"><?php esc_html_e( 'Inspect every incoming request before WordPress loads and reject known attack patterns.', 'qevix-shield' ); ?></p>
	<table class="form-table">
		<tr>
			<th scope="row"><?php esc_html_e( 'Enable Firewall', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Inspects each request\'s URL and query string for known attack patterns — e.g. <code>?id=1 UNION SELECT password…</code> (SQL injection) or <code>?page=../../wp-config.php</code> (path traversal) — and rejects matches with a 403 before WordPress finishes loading. Every block is written to the audit log.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="firewall_enabled" value="1" <?php checked( $settings->get( 'firewall_enabled', true ) ); ?> /> <?php esc_html_e( 'Block SQL injection, XSS, file inclusion, directory traversal and command injection patterns', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Runs at the earliest point a plugin can act — while WordPress is still loading plugins, before the rest of core executes. Blocked requests get a 403 and an audit-log entry. Whitelisted IPs (Login Protection tab) are never blocked; blocking earlier than this requires a server-level firewall.', 'qevix-shield' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Bad Bots', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Turns away requests that identify themselves as known attack tools — sqlmap, nikto, wpscan and similar vulnerability scanners. Search engines like Googlebot are NOT on the list and keep crawling normally. (Sophisticated attackers can fake their identity, so keep the firewall on too.)', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="firewall_block_bad_bots" value="1" <?php checked( $settings->get( 'firewall_block_bad_bots', true ) ); ?> /> <?php esc_html_e( 'Block requests from known attack tools and vulnerability scanners (sqlmap, nikto, wpscan, …)', 'qevix-shield' ); ?></label>
				<?php
				if ( $settings->get( 'firewall_block_bad_bots', false ) && ! $settings->get( 'firewall_enabled', false ) ) {
					QevixShield_Menu::dependency_notice( __( 'The <strong>Firewall is off</strong> above, so bad-bot blocking does not run. Enable the firewall for this to take effect.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Inspect POST Bodies', 'qevix-shield' ); ?></th>
			<td><?php QevixShield_Menu::help_tip( __( 'Extends the firewall to submitted form content, catching attacks hidden in POST data. Off by default because legitimate text can look like an attack — e.g. a reader pasting an SQL example into a comment would be blocked. Enable on sites without user-generated content; watch the log for false positives.', 'qevix-shield' ) ); ?>
				<label><input type="checkbox" name="firewall_inspect_post" value="1" <?php checked( $settings->get( 'firewall_inspect_post', false ) ); ?> /> <?php esc_html_e( 'Also run the firewall signatures against submitted form data', 'qevix-shield' ); ?></label>
				<p class="description"><?php esc_html_e( 'Off by default: legitimate content (comments about code, form plugins) can resemble attack payloads. URL and query-string inspection is always on while the firewall is enabled.', 'qevix-shield' ); ?></p>
				<?php
				if ( $settings->get( 'firewall_inspect_post', false ) && ! $settings->get( 'firewall_enabled', false ) ) {
					QevixShield_Menu::dependency_notice( __( 'The <strong>Firewall is off</strong> above, so POST-body inspection does not run. Enable the firewall for this to take effect.', 'qevix-shield' ) );
				}
				?>
			</td>
		</tr>
	</table>

	<?php submit_button( __( 'Save Changes', 'qevix-shield' ) ); ?>
</form>
