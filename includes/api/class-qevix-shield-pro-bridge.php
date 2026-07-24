<?php
/**
 * The hook/filter seam the qevix-shield-pro plugin attaches to. This is the
 * ONLY contract the free plugin exposes for pro integration — the free
 * plugin never checks for pro's presence directly, it just asks these
 * questions and lets pro answer them if it's loaded and licensed.
 *
 *   qevix_shield_is_pro_active     (filter) bool  — whether a licensed pro plugin is active
 *   qevix_shield_admin_pages       (filter) array — pages registered by class-qevix-shield-menu.php
 *   qevix_shield_settings_tabs     (filter) array — tabs inside the shared Settings page
 *
 * (Plus the per-module seams — settings overlays, save actions, enforcement
 * filters — documented at each module's hook site.)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Pro_Bridge {

	/**
	 * Default answer when no pro plugin is loaded: never active.
	 * The pro plugin hooks this same filter at a later priority and
	 * returns its own QevixShield_Pro_License::is_valid() result.
	 */
	public function is_pro_active( $active ) {
		return $active;
	}
}
