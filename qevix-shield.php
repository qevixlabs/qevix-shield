<?php
/**
 * Plugin Name:       Qevix Shield
 * Plugin URI:        https://qevixlabs.com/products/qevix-shield
 * Description:       Login protection, two-factor auth, reCAPTCHA, malware scanning, a firewall, and an audit log with alerts. Every protection off until you turn it on.
 * Version:           1.0.0
 * Requires at least: 6.8
 * Requires PHP:      8.1
 * Qevix Shield Pro Min: 1.0.0
 * Author:            QevixLabs
 * Author URI:        https://profiles.wordpress.org/qevixlabs
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       qevix-shield
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'QEVIX_SHIELD_VERSION', '1.0.0' );

/**
 * The oldest Qevix Shield Pro version this free release pairs with — the mirror
 * of Pro's `Requires Qevix Shield:` declaration, restated here as the custom
 * `Qevix Shield Pro Min:` header above (kept adjacent on purpose: bump BOTH
 * lines together). Deliberately NOT named "Requires": this plugin never
 * requires Pro — it is fully functional standalone, and nothing in the free
 * plugin ever reads Pro state. This is a passive declaration only; the Pro
 * plugin reads the constant to sharpen its version-mismatch guidance notice
 * ("this Qevix Shield pairs with Pro >= X — download the latest from your
 * customer panel"). Per the never-limit policy, no feature on either side is
 * ever disabled because of it.
 */
define( 'QEVIX_SHIELD_MIN_PRO_VERSION', '1.0.0' );

define( 'QEVIX_SHIELD_PLUGIN_FILE', __FILE__ );
define( 'QEVIX_SHIELD_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'QEVIX_SHIELD_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'QEVIX_SHIELD_TABLE_LOGS', 'qevix_shield_logs' );

// Marketing/product host, defined once so every product-page link derives from
// it (mirrors Pro's QEVIX_SHIELD_PRO_BASE_URL). Override in wp-config for staging.
if ( ! defined( 'QEVIX_SHIELD_BASE_URL' ) ) {
	define( 'QEVIX_SHIELD_BASE_URL', 'https://qevixlabs.com' );
}

// Where the "Get / Buy Pro" buttons point: the product page's pricing section
// (the #pricing anchor, so the buyer lands on the plans, not the top of the page).
// Derived from the base host (host lives in one place, not a full literal);
// filterable via `qevix_shield_buy_url` so it can be swapped without editing core.
if ( ! defined( 'QEVIX_SHIELD_BUY_URL' ) ) {
	define( 'QEVIX_SHIELD_BUY_URL', untrailingslashit( QEVIX_SHIELD_BASE_URL ) . '/products/qevix-shield#pricing' );
}

require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/class-qevix-shield-loader.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/class-qevix-shield-activator.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/class-qevix-shield-deactivator.php';
require_once QEVIX_SHIELD_PLUGIN_DIR . 'includes/class-qevix-shield.php';

register_activation_hook( __FILE__, array( 'QevixShield_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'QevixShield_Deactivator', 'deactivate' ) );

/**
 * Begins execution of the plugin.
 */
function qevix_shield_run() {
	$plugin = new QevixShield();
	$plugin->run();
}
qevix_shield_run();
