/**
 * reCAPTCHA v3: keep the hidden token field(s) filled. Each protected form
 * pushes its config { siteKey, action, fieldId } onto window.QevixShieldRecaptchaV3
 * (a page can host more than one form, e.g. WooCommerce my-account). api.js
 * loads in the footer, possibly after this script, so we poll for grecaptcha
 * rather than bail — bailing left the token empty until the first refresh,
 * failing every login until then. v3 tokens expire after ~2 min; refresh sooner.
 */
( function () {
	var fields = window.QevixShieldRecaptchaV3 || [];

	function refresh( f ) {
		if ( 'undefined' === typeof grecaptcha || 'undefined' === typeof grecaptcha.execute ) {
			window.setTimeout( function () {
				refresh( f );
			}, 250 );
			return;
		}
		grecaptcha.ready( function () {
			grecaptcha.execute( f.siteKey, { action: f.action } ).then( function ( token ) {
				var el = document.getElementById( f.fieldId );
				if ( el ) {
					el.value = token;
				}
			} );
		} );
	}

	fields.forEach( function ( f ) {
		refresh( f );
		window.setInterval( function () {
			refresh( f );
		}, 90000 );
	} );
} )();
