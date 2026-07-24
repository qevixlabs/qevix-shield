<?php
/**
 * Registers all actions and filters for the plugin, then fires them
 * against WordPress in one pass from QevixShield::run().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Loader {

	protected $actions = array();
	protected $filters = array();

	public function add_action( $hook, $component, $callback, $priority = 10, $acceptedArgs = 1 ) {
		$this->actions = $this->add( $this->actions, $hook, $component, $callback, $priority, $acceptedArgs );
	}

	public function add_filter( $hook, $component, $callback, $priority = 10, $acceptedArgs = 1 ) {
		$this->filters = $this->add( $this->filters, $hook, $component, $callback, $priority, $acceptedArgs );
	}

	private function add( $hooks, $hook, $component, $callback, $priority, $acceptedArgs ) {
		$hooks[] = array(
			'hook'          => $hook,
			'component'     => $component,
			'callback'      => $callback,
			'priority'      => $priority,
			'accepted_args' => $acceptedArgs,
		);
		return $hooks;
	}

	public function run() {
		foreach ( $this->filters as $hook ) {
			add_filter( $hook['hook'], array( $hook['component'], $hook['callback'] ), $hook['priority'], $hook['accepted_args'] );
		}

		foreach ( $this->actions as $hook ) {
			add_action( $hook['hook'], array( $hook['component'], $hook['callback'] ), $hook['priority'], $hook['accepted_args'] );
		}
	}
}
