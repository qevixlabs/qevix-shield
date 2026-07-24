<?php
/**
 * Dashboard view.
 *
 * Monitoring roles (VIEW_CAP) get the full dashboard — stat cards, pro widget
 * cards, and a tabbed activity section: Recent Activity is a notable-events
 * DIGEST (warning/critical only, repeats collapsed, relative times — the full
 * record lives on the Audit Log screen), My Activity is their own rows. Everyone
 * else who can open the Dashboard (any logged-in user) gets only their own
 * recent activity, as a plain non-tabular list.
 *
 * Expects from QevixShield_Dashboard::render(): $canView, $canManage,
 * $activityTab, $myRows, $myTotal, $myTotalPages, $myArgs, and — only when
 * $canView — $failed_24h, $success_24h, $lockouts_24h, $recent,
 * $sessions_count, $pro_widgets, $pro_widget_data.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$dashUrl = admin_url( 'admin.php?page=' . QevixShield_Menu::PARENT_SLUG );
?>
<div class="wrap qevix-shield-wrap">
	<h1><?php esc_html_e( 'Qevix Shield Dashboard', 'qevix-shield' ); ?></h1>

<?php if ( ! $canView ) : ?>

	<?php
	// Plain logged-in users: their own recent activity only, as a simple list.
	?>
	<h2 style="margin-top:20px;"><?php esc_html_e( 'My Activity', 'qevix-shield' ); ?></h2>
	<p class="description" style="margin:0 0 16px;">
		<?php esc_html_e( 'Sign-ins and other security events recorded for your account today.', 'qevix-shield' ); ?>
		<?php
		printf(
			/* translators: %s: link to the Sessions page */
			esc_html__( 'If you see activity you do not recognize, change your password and review your %s.', 'qevix-shield' ),
			'<a href="' . esc_url( admin_url( 'admin.php?page=qevix-shield-sessions' ) ) . '">' . esc_html__( 'active sessions', 'qevix-shield' ) . '</a>'
		);
		?>
	</p>

	<?php require __DIR__ . '/my-activity-table.php'; ?>

<?php else : ?>

	<?php
	// Status accent colors for the pro widgets, keyed by the 'status' each
	// reports. 'neutral' (or anything unknown) gets no accent.
	$statusColors = array(
		'good' => '#46b450',
		'warn' => '#ffb900',
		'bad'  => '#dc3232',
	);

	// Succeeded/failed shares of all attempts, driving the two bars below.
	$attemptsTotal = $success_24h + $failed_24h;
	$successPct    = $attemptsTotal ? (int) round( $success_24h / $attemptsTotal * 100 ) : 0;
	$failedPct     = $attemptsTotal ? (int) round( $failed_24h / $attemptsTotal * 100 ) : 0;
	?>
	<div class="qevix-shield-widgets">
		<?php if ( $canManage ) : ?>
		<a class="card qevix-shield-card-link" style="border-left:4px solid #2271b1;" href="<?php echo esc_url( admin_url( 'admin.php?page=qevix-shield-login-protection' ) ); ?>">
		<?php else : ?>
		<div class="card" style="border-left:4px solid #2271b1;">
		<?php endif; ?>
			<h3><span class="dashicons dashicons-lock"></span> <?php esc_html_e( 'Login Attempts (24h)', 'qevix-shield' ); ?></h3>
			<div class="qevix-shield-bar-row">
				<span class="qevix-shield-bar-label"><?php esc_html_e( 'succeeded', 'qevix-shield' ); ?></span>
				<span class="qevix-shield-metric qevix-shield-metric-good"><?php echo esc_html( (string) $success_24h ); ?></span>
			</div>
			<div class="qevix-shield-progress">
				<span class="qevix-shield-progress-fill qevix-shield-fill-good" style="width:<?php echo esc_attr( (string) (int) $successPct ); ?>%;"></span>
			</div>
			<div class="qevix-shield-bar-row">
				<span class="qevix-shield-bar-label"><?php esc_html_e( 'failed', 'qevix-shield' ); ?></span>
				<span class="qevix-shield-metric qevix-shield-metric-bad"><?php echo esc_html( (string) $failed_24h ); ?></span>
			</div>
			<div class="qevix-shield-progress">
				<span class="qevix-shield-progress-fill qevix-shield-fill-bad" style="width:<?php echo esc_attr( (string) (int) $failedPct ); ?>%;"></span>
			</div>
		<?php echo $canManage ? '</a>' : '</div>'; ?>
		<?php if ( $canManage ) : ?>
		<a class="card qevix-shield-card-link" style="border-left:4px solid #dc3232;" href="<?php echo esc_url( admin_url( 'admin.php?page=qevix-shield-logs&filter_action=ip_locked_out' ) ); ?>">
		<?php else : ?>
		<div class="card" style="border-left:4px solid #dc3232;">
		<?php endif; ?>
			<h3><span class="dashicons dashicons-shield"></span> <?php esc_html_e( 'IP Lockouts (24h)', 'qevix-shield' ); ?></h3>
			<p class="qevix-shield-big-num qevix-shield-metric-bad"><?php echo esc_html( (string) $lockouts_24h ); ?></p>
		<?php echo $canManage ? '</a>' : '</div>'; ?>
		<a class="card qevix-shield-card-link" style="border-left:4px solid #46b450;" href="<?php echo esc_url( admin_url( 'admin.php?page=qevix-shield-sessions' ) ); ?>">
			<h3><span class="dashicons dashicons-desktop"></span> <?php esc_html_e( 'Your Active Sessions', 'qevix-shield' ); ?></h3>
			<p class="qevix-shield-big-num">
				<span class="qevix-shield-live-dot" aria-hidden="true"></span>
				<?php echo esc_html( (string) $sessions_count ); ?>
			</p>
		</a>

		<?php
		// The pro widget cards ALWAYS render (both tiers). When pro supplies
		// data for a widget key it shows the real figure; otherwise the card
		// stays locked with an upsell — so the same set of boxes is visible on
		// free and pro, and only their contents change.
		foreach ( $pro_widgets as $key => $def ) :
			$data = isset( $pro_widget_data[ $key ] ) && is_array( $pro_widget_data[ $key ] )
				? $pro_widget_data[ $key ]
				: null;

			if ( null === $data || ! isset( $data['value'] ) || '' === $data['value'] ) :
				// Locked / upsell state (free tier, or pro not licensed).
				?>
				<div class="card qevix-shield-locked">
					<h3><span class="dashicons dashicons-lock"></span> <?php echo esc_html( $def['label'] ); ?></h3>
					<p>
						<?php if ( $canManage ) : ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=qevix-shield-license' ) ); ?>">
								<?php esc_html_e( 'Upgrade to Pro', 'qevix-shield' ); ?>
							</a>
						<?php else : ?>
							<span class="description"><?php esc_html_e( 'Pro feature', 'qevix-shield' ); ?></span>
						<?php endif; ?>
					</p>
				</div>
				<?php
			else :
				// Active state — real data from the pro widget provider.
				$status = isset( $data['status'] ) ? $data['status'] : 'neutral';
				$accent = isset( $statusColors[ $status ] ) ? $statusColors[ $status ] : '';
				?>
				<?php if ( $canManage ) : ?>
				<a class="card qevix-shield-widget-pro qevix-shield-card-link" href="<?php echo esc_url( admin_url( 'admin.php?page=' . ( isset( $def['page'] ) ? $def['page'] : 'qevix-shield-settings' ) ) ); ?>" style="<?php echo $accent ? 'border-left:4px solid ' . esc_attr( $accent ) . ';' : ''; ?>">
				<?php else : ?>
				<div class="card qevix-shield-widget-pro" style="<?php echo $accent ? 'border-left:4px solid ' . esc_attr( $accent ) . ';' : ''; ?>">
				<?php endif; ?>
					<h3><span class="dashicons <?php echo esc_attr( $def['icon'] ); ?>"></span> <?php echo esc_html( $def['label'] ); ?></h3>
					<p class="qevix-shield-big-num" style="<?php echo $accent ? 'color:' . esc_attr( $accent ) . ';' : ''; ?>">
						<?php if ( ! empty( $data['badge'] ) ) : ?>
							<?php
							$badgeIcons = array(
								'good' => 'dashicons-yes-alt',
								'warn' => 'dashicons-warning',
								'bad'  => 'dashicons-dismiss',
							);
							?>
							<span class="dashicons <?php echo esc_attr( isset( $badgeIcons[ $status ] ) ? $badgeIcons[ $status ] : 'dashicons-marker' ); ?> qevix-shield-status-badge qevix-shield-badge-<?php echo esc_attr( $status ); ?>" aria-hidden="true"></span>
						<?php endif; ?>
						<?php echo esc_html( $data['value'] ); ?>
					</p>
					<?php if ( ! empty( $data['sub'] ) ) : ?>
						<p style="margin:0;color:#666;font-size:12px;"><?php echo esc_html( $data['sub'] ); ?></p>
					<?php endif; ?>
					<?php if ( ! empty( $data['progress'] ) && is_array( $data['progress'] ) && 2 === count( $data['progress'] ) ) : ?>
						<?php
						list( $progressOn, $progressTotal ) = array_values( $data['progress'] );
						$progressPct                        = $progressTotal > 0 ? (int) round( $progressOn / $progressTotal * 100 ) : 0;
						?>
						<div class="qevix-shield-progress" role="img" aria-label="<?php echo esc_attr( sprintf( '%d/%d', $progressOn, $progressTotal ) ); ?>">
							<span class="qevix-shield-progress-fill qevix-shield-fill-<?php echo esc_attr( $status ); ?>" style="width:<?php echo esc_attr( (string) (int) $progressPct ); ?>%;"></span>
						</div>
					<?php endif; ?>
				<?php echo $canManage ? '</a>' : '</div>'; ?>
				<?php
			endif;
		endforeach;
		?>
	</div>

	<h2 style="margin-top:24px;"><?php esc_html_e( 'Activity', 'qevix-shield' ); ?></h2>
	<nav class="nav-tab-wrapper">
		<a href="<?php echo esc_url( add_query_arg( 'activity', 'recent', $dashUrl ) ); ?>" class="nav-tab <?php echo 'recent' === $activityTab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Recent Activity', 'qevix-shield' ); ?></a>
		<a href="<?php echo esc_url( add_query_arg( 'activity', 'mine', $dashUrl ) ); ?>" class="nav-tab <?php echo 'mine' === $activityTab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'My Activity', 'qevix-shield' ); ?></a>
	</nav>

	<?php if ( 'mine' === $activityTab ) : ?>

		<p class="description" style="margin:12px 0 12px;">
			<?php esc_html_e( 'Security events recorded for your own account today.', 'qevix-shield' ); ?>
		</p>
		<?php require __DIR__ . '/my-activity-table.php'; ?>

	<?php else : ?>

		<div class="qevix-shield-flex-row qevix-shield-digest-head">
			<p class="description">
				<?php esc_html_e( 'Warnings and critical events, newest first, with repeats collapsed — routine activity is not shown here.', 'qevix-shield' ); ?>
			</p>
			<?php if ( $canManage ) : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=qevix-shield-logs' ) ); ?>" class="qevix-shield-see-more">
					<?php esc_html_e( 'View full audit log', 'qevix-shield' ); ?> <span aria-hidden="true">&rarr;</span>
				</a>
			<?php endif; ?>
		</div>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'When', 'qevix-shield' ); ?></th>
					<th><?php esc_html_e( 'Event', 'qevix-shield' ); ?></th>
					<th><?php esc_html_e( 'User', 'qevix-shield' ); ?></th>
					<th><?php esc_html_e( 'IP', 'qevix-shield' ); ?></th>
					<th><?php esc_html_e( 'Severity', 'qevix-shield' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $recent ) ) : ?>
					<tr><td colspan="5"><?php esc_html_e( 'No warnings or critical events in the log — nothing needs your attention right now.', 'qevix-shield' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $recent as $group ) : ?>
						<tr>
							<td>
								<?php
								printf(
									/* translators: %s: human-readable time difference, e.g. "12 mins". */
									esc_html__( '%s ago', 'qevix-shield' ),
									esc_html( human_time_diff( strtotime( $group->last_time ), current_time( 'timestamp' ) ) )
								);
								?>
							</td>
							<td>
								<?php echo esc_html( $group->action ); ?>
								<?php if ( $group->count > 1 ) : ?>
									<span class="qevix-shield-report-count">
										<?php
										printf(
											/* translators: %d: how many times the event repeated. */
											esc_html__( '×%d', 'qevix-shield' ),
											(int) $group->count
										);
										?>
									</span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $group->username ); ?></td>
							<td><?php echo esc_html( $group->ip ); ?></td>
							<td><span class="qevix-shield-sev-badge qevix-shield-sev-<?php echo esc_attr( $group->severity ); ?>"><?php echo esc_html( $group->severity ); ?></span></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>

	<?php endif; ?>

<?php endif; ?>
</div>
