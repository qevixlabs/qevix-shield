<?php
/**
 * Generic tabbed Settings page. Tabs come from the `qevix_shield_settings_tabs`
 * filter (free + pro), already filtered by capability, so this file never
 * needs to know which modules exist.
 * Expects: $tabs (sorted, visible), $active (slug), $base_url, $is_pro_active.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap qevix-shield-wrap">
	<h1><?php esc_html_e( 'Qevix Shield Settings', 'qevix-shield' ); ?></h1>

	<?php if ( isset( $_GET['updated'] ) ) : ?>
		<?php
		// Name the tab that was saved instead of a bare "Settings saved." —
		// the redirect lands on the saved tab, so $active is that tab.
		$savedLabel = '';
		foreach ( $tabs as $tab ) {
			if ( $tab['slug'] === $active ) {
				$savedLabel = (string) $tab['label'];
				break;
			}
		}
		?>
		<div class="notice notice-success is-dismissible"><p>
			<?php
			if ( '' !== $savedLabel ) {
				printf(
					/* translators: %s: settings tab name */
					esc_html__( '%s settings saved.', 'qevix-shield' ),
					esc_html( $savedLabel )
				);
			} else {
				esc_html_e( 'Settings saved.', 'qevix-shield' );
			}
			?>
		</p></div>
	<?php endif; ?>

	<h2 class="nav-tab-wrapper">
		<?php
		foreach ( $tabs as $tab ) :
			$isProTab = ! empty( $tab['pro'] );
			$classes    = 'nav-tab';
			if ( $active === $tab['slug'] ) {
				$classes .= ' nav-tab-active';
			}
			if ( $isProTab && ! $is_pro_active ) {
				$classes .= ' qevix-shield-tab-locked';
			}
			?>
			<a href="<?php echo esc_url( add_query_arg( 'tab', $tab['slug'], $base_url ) ); ?>" class="<?php echo esc_attr( $classes ); ?>">
				<?php if ( $isProTab ) : ?>
					<span class="dashicons <?php echo $is_pro_active ? 'dashicons-star-filled' : 'dashicons-lock'; ?> qevix-shield-tab-badge"></span>
				<?php endif; ?>
				<?php echo esc_html( $tab['label'] ); ?>
			</a>
		<?php endforeach; ?>
	</h2>

	<div class="qevix-shield-tab-body">
		<?php
		foreach ( $tabs as $tab ) {
			if ( $tab['slug'] === $active && is_callable( $tab['render'] ) ) {
				call_user_func( $tab['render'] );
			}
		}
		?>
	</div>
</div>
