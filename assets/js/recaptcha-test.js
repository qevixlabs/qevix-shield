/**
 * reCAPTCHA "Test keys" preflight (reCAPTCHA settings tab).
 *
 * Why this exists: a v2/v3 key-type mismatch fails entirely in the BROWSER —
 * Google's api.js refuses the key, no token is ever minted, and the login POST
 * arrives with an empty token field. The server cannot tell that apart from an
 * attacker stripping the field, so it fails closed and every user is locked out
 * of the login form, admin included. The only place to catch it is here, before
 * the config is allowed to go live.
 *
 * The test runs against the SAVED keys and version — save first, then test.
 * That ordering is deliberate and does real work:
 *
 *  - api.js takes the version (and for v3 the site key) from its script URL and
 *    can only be configured ONCE per JS context. Because the saved values are
 *    the only thing tested, and changing them requires a save, and a save
 *    redirects, every page load starts with a clean context and the limit can
 *    never be hit. No reload prompt, no stale-config false pass.
 *  - The fingerprint the server records therefore always describes the stored
 *    config, so nothing can be tested under one set of values and enabled under
 *    another.
 *
 * v3 is automatic (grecaptcha.execute needs no interaction). v2 needs a real
 * click by design — the checkbox renders inline and the admin ticks it, seeing
 * exactly what visitors will see. If the key type is wrong, Google draws its own
 * "ERROR for site owner" tile and mints nothing, which leaves the switch locked.
 * Failing that way is the point.
 */
( function () {
	'use strict';

	var cfg = window.QevixShieldRecaptchaTest || {};

	var btn = document.getElementById( 'qevix-shield-rc-test' );
	var out = document.getElementById( 'qevix-shield-rc-test-result' );
	var box = document.getElementById( 'qevix-shield-rc-test-widget' );
	if ( ! btn || ! out || ! box ) {
		return;
	}

	var apiLoaded = false;
	var widgetId  = null;

	function say( text, kind ) {
		out.textContent = text;
		out.className = 'qevix-shield-rc-result qevix-shield-rc-' + kind;
	}

	function busy( isBusy ) {
		btn.disabled = isBusy;
		btn.textContent = isBusy ? cfg.i18n.testing : cfg.i18n.test;
	}

	/**
	 * Has the admin edited the form away from what is saved? The test can only
	 * speak for the saved values, so say so rather than testing one thing and
	 * reporting it as another. A typed secret always counts as a change: the
	 * field is write-only and renders blank, so any content in it is new.
	 */
	function isDirty() {
		var siteEl    = document.getElementById( 'recaptcha_site_key' );
		var secretEl  = document.getElementById( 'recaptcha_secret_key' );
		var versionEl = document.querySelector( 'input[name="recaptcha_version"]:checked' );

		if ( siteEl && siteEl.value.trim() !== cfg.savedSiteKey ) {
			return true;
		}
		if ( secretEl && '' !== secretEl.value ) {
			return true;
		}
		if ( versionEl && versionEl.value !== cfg.savedVersion ) {
			return true;
		}
		return false;
	}

	/** Only the token travels — the server reads the trio from settings. */
	function verify( token ) {
		var body = new URLSearchParams();
		body.append( 'action', 'qevix_shield_recaptcha_test' );
		body.append( '_ajax_nonce', cfg.nonce );
		body.append( 'token', token || '' );

		fetch( cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		} ).then( function ( r ) {
			return r.json();
		} ).then( function ( res ) {
			busy( false );
			if ( res && res.success ) {
				say( res.data.message, 'ok' );
				box.hidden = true;
			} else {
				say( ( res && res.data && res.data.message ) || cfg.i18n.failed, 'bad' );
			}
		} ).catch( function () {
			busy( false );
			say( cfg.i18n.failed, 'bad' );
		} );
	}

	function loadApi() {
		return new Promise( function ( resolve, reject ) {
			if ( apiLoaded ) {
				resolve();
				return;
			}
			var url = 'v3' === cfg.savedVersion
				? 'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent( cfg.savedSiteKey )
				: 'https://www.google.com/recaptcha/api.js?render=explicit';

			var s = document.createElement( 'script' );
			s.src = url;
			s.async = true;
			s.onload = function () {
				var tries = 0;
				( function wait() {
					if ( window.grecaptcha && ( window.grecaptcha.render || window.grecaptcha.ready ) ) {
						apiLoaded = true;
						resolve();
					} else if ( tries++ < 100 ) {
						setTimeout( wait, 100 );
					} else {
						reject();
					}
				} )();
			};
			// The <script> failed outright. NOT necessarily a connectivity
			// problem: Google answers the v3 loader URL with HTTP 400 when the
			// site key is a v2 key, which fails the tag exactly the same way. A
			// failed script exposes no status to JS, so let the server re-fetch
			// the same URL and tell those apart (see explain_missing_token()).
			s.onerror = reject;
			document.head.appendChild( s );
		} );
	}

	function runV3() {
		var settled = false;
		var done = function ( token ) {
			if ( settled ) {
				return;
			}
			settled = true;
			verify( token );
		};

		setTimeout( function () {
			done( '' );
		}, 12000 );

		try {
			window.grecaptcha.ready( function () {
				try {
					window.grecaptcha.execute( cfg.savedSiteKey, { action: 'qevix_shield_test' } )
						.then( done )
						.catch( function () {
							done( '' );
						} );
				} catch ( e ) {
					done( '' );
				}
			} );
		} catch ( e ) {
			done( '' );
		}
	}

	function runV2() {
		box.hidden = false;
		say( cfg.i18n.tickBox, 'info' );
		busy( false );

		// Re-testing the same saved key in one page load: reset rather than
		// render a second widget into the same node (which throws).
		if ( null !== widgetId ) {
			try {
				window.grecaptcha.reset( widgetId );
			} catch ( e ) {}
			return;
		}

		try {
			widgetId = window.grecaptcha.render( box, {
				sitekey: cfg.savedSiteKey,
				callback: function ( token ) {
					busy( true );
					say( cfg.i18n.checking, 'info' );
					verify( token );
				},
				'error-callback': function () {
					verify( '' );
				}
			} );
		} catch ( e ) {
			// A v3 key throws here rather than rendering a checkbox.
			verify( '' );
		}
	}

	btn.addEventListener( 'click', function () {
		if ( ! cfg.savedSiteKey || ! cfg.hasSavedSecret ) {
			say( cfg.i18n.needKeys, 'bad' );
			return;
		}
		if ( isDirty() ) {
			say( cfg.i18n.saveFirst, 'bad' );
			return;
		}

		busy( true );
		say( cfg.i18n.checking, 'info' );

		loadApi().then( function () {
			if ( 'v3' === cfg.savedVersion ) {
				runV3();
			} else {
				runV2();
			}
		} ).catch( function () {
			// Let the server explain WHY nothing loaded.
			verify( '' );
		} );
	} );

	// Editing the form invalidates any result on screen — it described the
	// saved values, which these no longer are.
	function invalidate() {
		if ( isDirty() ) {
			say( cfg.i18n.saveFirst, 'info' );
			box.hidden = true;
		}
	}
	[ 'recaptcha_site_key', 'recaptcha_secret_key' ].forEach( function ( id ) {
		var el = document.getElementById( id );
		if ( el ) {
			el.addEventListener( 'input', invalidate );
		}
	} );
	Array.prototype.forEach.call(
		document.querySelectorAll( 'input[name="recaptcha_version"]' ),
		function ( el ) {
			el.addEventListener( 'change', invalidate );
		}
	);
} )();
