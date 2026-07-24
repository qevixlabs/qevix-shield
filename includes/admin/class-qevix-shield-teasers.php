<?php
/**
 * Freemium upsell teaser for the Pro / License tab.
 *
 * The free plugin registers a locked placeholder `license` tab + submenu so a
 * free-only user sees the Pro / License menu (with a lock and a Buy CTA). When
 * the pro plugin is present it registers the SAME slug with the real activation
 * form; the menu builder's dedupe (preferring non-placeholder) then swaps this
 * placeholder out. Marked 'placeholder' => true and 'pro' => true.
 *
 * Two-Factor Auth and reCAPTCHA used to be teasers here too, but since 2026-07-16
 * they are real, free-owned tabs (base features work with no license), registered
 * by their own free modules — so they are NOT teasers and carry no lock badge.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Teasers {

	/* --------------------------- settings tabs --------------------------- */

	/**
	 * The only remaining teaser is Pro / License. Two-Factor Auth and reCAPTCHA
	 * are NOT teasers anymore — they are real, free-owned tabs (base 2FA + the v2
	 * reCAPTCHA checkbox work with no license; each tab carries an inline "— Pro"
	 * box for the advanced knobs the pro plugin unlocks), registered by their own
	 * free modules.
	 */
	public function register_settings_tabs( $tabs ) {
		// Pro / License is always last. Free shows a "Buy" panel here; when pro
		// is installed its real activation form replaces this.
		$tabs[] = array(
			'slug'        => 'license',
			'label'       => __( 'Qevix Shield Pro', 'qevix-shield' ),
			'render'      => array( $this, 'render_buy_section' ),
			'capability'  => QevixShield_Settings::CAP,
			'pro'         => true,
			'placeholder' => true,
			'position'    => 1000,
		);

		return $tabs;
	}

	/* ------------------------------ submenus ----------------------------- */

	public function register_admin_pages( $pages ) {
		$pages[] = array(
			'slug'        => 'qevix-shield-license',
			'page_title'  => __( 'Qevix Shield Pro', 'qevix-shield' ),
			'menu_title'  => __( 'Qevix Shield Pro', 'qevix-shield' ),
			'capability'  => QevixShield_Settings::CAP,
			'callback'    => static function () {
				QevixShield_Menu::render_tabbed_settings( 'license' );
			},
			'pro'         => true,
			'placeholder' => true,
			'tab'         => 'license',
			'position'    => 1000,
		);

		return $pages;
	}


	public function render_buy_section() {
		$buyUrl = esc_url( apply_filters( 'qevix_shield_buy_url', QEVIX_SHIELD_BUY_URL ) );

		// Is the Pro plugin present on disk but inactive? It can't be active here
		// (an active Pro plugin registers its own License tab and dedupes this
		// teaser out), so "installed" means "installed but not activated" — the
		// user only needs to activate it, not install it.
		$proFile      = 'qevix-shield-pro/qevix-shield-pro.php';
		$proInstalled = file_exists( WP_PLUGIN_DIR . '/' . $proFile );
		?>
		<div class="card qevix-shield-panel qevix-shield-panel-narrow">
			<h2><?php esc_html_e( 'Upgrade to Qevix Shield Pro', 'qevix-shield' ); ?></h2>
			<p><?php esc_html_e( 'Everything this plugin does is already yours. Qevix Shield Pro is a separate add-on that layers extra capabilities on top:', 'qevix-shield' ); ?></p>
			<?php QevixShield_Menu::render_pro_feature_list(); ?>
			<p class="description"><?php esc_html_e( 'Plans for every site — including a Lifetime option. The additions above start working the moment you activate.', 'qevix-shield' ); ?></p>
			<p>
				<a href="<?php echo $buyUrl; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- already esc_url'd. ?>" class="button button-primary button-hero" target="_blank" rel="noopener">
					<?php esc_html_e( 'Buy Qevix Shield Pro', 'qevix-shield' ); ?>
				</a>
			</p>
			<hr />
			<p class="description">
				<?php if ( $proInstalled ) : ?>
					<?php esc_html_e( 'Already bought it? The Qevix Shield Pro plugin is installed but not active — activate it, then enter your license key on this tab.', 'qevix-shield' ); ?>
					<?php if ( current_user_can( 'activate_plugins' ) ) : ?>
						<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'plugins.php?action=activate&plugin=' . rawurlencode( $proFile ) ), 'activate-plugin_' . $proFile ) ); ?>"><?php esc_html_e( 'Activate Qevix Shield Pro', 'qevix-shield' ); ?></a>
					<?php endif; ?>
				<?php else : ?>
					<?php esc_html_e( 'Already bought it? Install and activate the Qevix Shield Pro plugin, then enter your license key on this tab.', 'qevix-shield' ); ?>
				<?php endif; ?>
			</p>
		</div>
		<?php
	}
}
