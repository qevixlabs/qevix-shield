/**
 * Renders the enrolment QR code from the otpauth URI localized as
 * window.QevixShield2FAQR.otpauth. Shared by the standalone forced-enrolment
 * screen and the Two-Factor Auth settings tab. No-ops when there is no pending
 * secret (config or target element absent) or the QRCode library is missing.
 */
( function () {
	function render() {
		var cfg = window.QevixShield2FAQR;
		var el  = document.getElementById( 'qevix-shield-2fa-qr' );
		if ( ! cfg || ! cfg.otpauth || ! el || 'undefined' === typeof QRCode ) {
			return;
		}
		new QRCode( el, { text: cfg.otpauth, width: 180, height: 180 } );
	}
	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', render );
	} else {
		render();
	}
} )();
