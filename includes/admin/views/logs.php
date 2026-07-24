<?php
/**
 * Audit Log tab content (form only — no page chrome; shared by the standalone
 * submenu page and the Settings > Audit Log tab, same pattern as every other tab).
 * Search/filter and CSV export. Expects $rows, $total,
 * $total_pages, $args from QevixShield_Menu::render_logs_section().
 *
 * Title + search/filter row sit side by side in a 50/50 flex layout instead
 * of stacking (WP core's `.search-box` float:right only lines up next to a
 * `wp-heading-inline` <h1>, which this tab doesn't use, so it was dropping
 * to its own line with a lot of empty space either side).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$exportUrl = wp_nonce_url(
	add_query_arg(
		array(
			'action'        => 'qevix_shield_export_csv',
			's'             => $args['search'],
			'filter_action' => $args['action'],
			'severity'      => $args['severity'],
			'module'        => $args['module'],
		),
		admin_url( 'admin-post.php' )
	),
	'qevix_shield_export_csv'
);
?>
<div class="qevix-shield-toolbar">
	<div>
		<h3>
			<?php esc_html_e( 'Qevix Shield Audit Log', 'qevix-shield' ); ?>
			<span id="qevix-shield-live-indicator" class="qevix-shield-live" title="<?php esc_attr_e( 'Live — new entries appear automatically', 'qevix-shield' ); ?>">
				<span class="qevix-shield-live-dot"></span> <?php esc_html_e( 'Live', 'qevix-shield' ); ?>
			</span>
		</h3>
		<p class="description">
			<?php
			$retention_days = isset( $retention_days ) ? (int) $retention_days : 7;
			printf(
				/* translators: %d: number of days of activity retained. */
				esc_html( _n( 'Retains %d day of activity (configurable under Settings → General).', 'Retains %d days of activity (configurable under Settings → General).', $retention_days, 'qevix-shield' ) ),
				absint( $retention_days )
			);
			?>
		</p>
	</div>

	<form method="get">
		<input type="hidden" name="page" value="qevix-shield-logs" />
		<input type="hidden" name="tab" value="logs" />
		<p class="search-box">
			<input type="search" name="s" value="<?php echo esc_attr( $args['search'] ); ?>" placeholder="<?php esc_attr_e( 'Search username, IP, action, status…', 'qevix-shield' ); ?>" />
			<select name="severity">
				<option value=""><?php esc_html_e( 'All Severities', 'qevix-shield' ); ?></option>
				<?php foreach ( array( 'info', 'warning', 'critical' ) as $sev ) : ?>
					<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( $args['severity'], $sev ); ?>><?php echo esc_html( ucfirst( $sev ) ); ?></option>
				<?php endforeach; ?>
			</select>
			<select name="module">
				<option value=""><?php esc_html_e( 'All Modules', 'qevix-shield' ); ?></option>
				<?php
				// Every module value the loggers actually write — keep in sync
				// with the QevixShield_Audit_Log::log() call sites (both plugins).
				$logModules = array(
					'auth'          => __( 'Auth', 'qevix-shield' ),
					'admin'         => __( 'Admin', 'qevix-shield' ),
					'firewall'      => __( 'Firewall', 'qevix-shield' ),
					'file_security' => __( 'File Security', 'qevix-shield' ),
					'hardening'     => __( 'Hardening', 'qevix-shield' ),
					'malware'       => __( 'Malware', 'qevix-shield' ),
					'xmlrpc'        => __( 'XML-RPC', 'qevix-shield' ),
					'system'        => __( 'System', 'qevix-shield' ),
					'qevix-shield'    => __( 'QevixShield', 'qevix-shield' ),
				);
				foreach ( $logModules as $mod => $modLabel ) :
					?>
					<option value="<?php echo esc_attr( $mod ); ?>" <?php selected( $args['module'], $mod ); ?>><?php echo esc_html( $modLabel ); ?></option>
				<?php endforeach; ?>
			</select>
			<button type="submit" class="button"><?php esc_html_e( 'Filter', 'qevix-shield' ); ?></button>
			<a href="<?php echo esc_url( $exportUrl ); ?>" class="button"><?php esc_html_e( 'Export CSV', 'qevix-shield' ); ?></a>
		</p>
	</form>
</div>

<table class="widefat striped">
	<thead>
		<tr>
			<th><?php esc_html_e( 'Time', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'User', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'IP', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Browser', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Action', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Module', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Severity', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Status', 'qevix-shield' ); ?></th>
		</tr>
	</thead>
	<tbody id="qevix-shield-logs-body">
		<?php if ( empty( $rows ) ) : ?>
			<tr class="qevix-shield-logs-empty"><td colspan="8"><?php esc_html_e( 'No log entries match this filter.', 'qevix-shield' ); ?></td></tr>
		<?php else : ?>
			<?php foreach ( $rows as $row ) : ?>
				<tr data-log-id="<?php echo (int) $row->id; ?>">
					<td><?php echo esc_html( $row->timestamp ); ?></td>
					<td><?php echo esc_html( $row->username ); ?></td>
					<td><?php echo esc_html( $row->ip ); ?></td>
					<td><?php echo esc_html( $row->browser ); ?></td>
					<td><?php echo esc_html( $row->action ); ?></td>
					<td><?php echo esc_html( $row->module ); ?></td>
					<td><?php echo esc_html( $row->severity ); ?></td>
					<td><?php echo esc_html( $row->status ); ?></td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
	</tbody>
</table>

<?php if ( $total_pages > 1 ) : ?>
	<div class="tablenav">
		<div class="tablenav-pages">
			<?php
			echo wp_kses_post(
				paginate_links(
					array(
						'base'    => add_query_arg( 'paged', '%#%' ),
						'format'  => '',
						'current' => max( 1, $args['paged'] ),
						'total'   => $total_pages,
					)
				)
			);
			?>
		</div>
	</div>
<?php endif; ?>
