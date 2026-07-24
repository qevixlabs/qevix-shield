<?php
/**
 * My Activity table — the current user's own audit-log rows, with pagination.
 * A shared partial: the Dashboard renders it both for the admin "My Activity"
 * tab and for the plain-user (read-only) My Activity view, so the two always
 * look identical. Expects $myRows, $myArgs, $myTotalPages.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<table class="widefat striped">
	<thead>
		<tr>
			<th><?php esc_html_e( 'When', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Action', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'IP', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Browser', 'qevix-shield' ); ?></th>
			<th><?php esc_html_e( 'Status', 'qevix-shield' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php if ( empty( $myRows ) ) : ?>
			<tr><td colspan="5"><?php esc_html_e( 'No activity recorded for your account today.', 'qevix-shield' ); ?></td></tr>
		<?php else : ?>
			<?php foreach ( $myRows as $row ) : ?>
				<tr>
					<td>
						<?php
						printf(
							/* translators: %s: human-readable time difference, e.g. "12 mins". */
							esc_html__( '%s ago', 'qevix-shield' ),
							esc_html( human_time_diff( strtotime( $row->timestamp ), current_time( 'timestamp' ) ) )
						);
						?>
					</td>
					<td><?php echo esc_html( $row->action ); ?></td>
					<td><?php echo esc_html( $row->ip ); ?></td>
					<td><?php echo esc_html( $row->browser ); ?></td>
					<td><?php echo esc_html( $row->status ); ?></td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
	</tbody>
</table>

<?php if ( $myTotalPages > 1 ) : ?>
	<div class="tablenav"><div class="tablenav-pages">
	<?php
	echo wp_kses_post(
		paginate_links(
			array(
				'base'    => add_query_arg( 'paged', '%#%' ),
				'format'  => '',
				'current' => max( 1, $myArgs['paged'] ),
				'total'   => $myTotalPages,
			)
		)
	);
	?>
	</div></div>
<?php endif; ?>
