/**
 * Notifications tab: each provider dropdown decides which "Need help?" link
 * is relevant, so only the selected choice's link is shown — the SMS Gateway
 * select (Twilio Console vs Meta app dashboard) and the webhook Payload
 * Format select (Slack / Discord / generic capture URL). The initial hidden
 * state is rendered server-side from the saved value; this only keeps it in
 * sync while the admin changes a dropdown before saving.
 */
( function () {
	'use strict';

	/**
	 * Wire a select so that, of the given value=>element-id map, only the
	 * link matching the current selection is visible.
	 */
	function wire( selectId, linkIds ) {
		var select = document.getElementById( selectId );
		if ( ! select ) {
			return;
		}
		var links = {};
		for ( var value in linkIds ) {
			links[ value ] = document.getElementById( linkIds[ value ] );
			if ( ! links[ value ] ) {
				return;
			}
		}

		function sync() {
			for ( var value in links ) {
				links[ value ].hidden = value !== select.value;
			}
		}

		select.addEventListener( 'change', sync );
		sync();
	}

	function init() {
		wire( 'notify_sms_provider', {
			twilio:   'qevix-shield-sms-help-twilio',
			whatsapp: 'qevix-shield-sms-help-whatsapp'
		} );
		wire( 'notify_webhook_format', {
			generic: 'qevix-shield-web-help-generic',
			slack:   'qevix-shield-web-help-slack',
			discord: 'qevix-shield-web-help-discord'
		} );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
