/**
 * "?" help-tip popovers used on every Qevix Shield settings tab.
 *
 * CSS already shows the popover on :hover / :focus-within; this adds a
 * click / Enter / Space toggle (touch devices, and keeping a tip open while
 * moving the pointer to read it), closes on Escape or an outside click, and
 * keeps at most one tip pinned open. Icons are spans (not buttons) so they
 * keep working inside `<fieldset disabled>` — hence the manual key handling.
 */
( function () {
	'use strict';

	var OPEN = 'qevix-shield-help-open';

	function closeAll( except ) {
		document.querySelectorAll( '.qevix-shield-help.' + OPEN ).forEach( function ( tip ) {
			if ( tip !== except ) {
				tip.classList.remove( OPEN );
				var icon = tip.querySelector( '.qevix-shield-help-icon' );
				if ( icon ) {
					icon.setAttribute( 'aria-expanded', 'false' );
				}
			}
		} );
	}

	function toggle( tip ) {
		var isOpen = tip.classList.toggle( OPEN );
		closeAll( tip );
		var icon = tip.querySelector( '.qevix-shield-help-icon' );
		if ( icon ) {
			icon.setAttribute( 'aria-expanded', isOpen ? 'true' : 'false' );
		}
		if ( isOpen ) {
			flipIfClipped( tip );
		}
	}

	// If the popover would run off the right edge of the viewport, anchor it
	// to the icon's right side instead.
	function flipIfClipped( tip ) {
		var pop = tip.querySelector( '.qevix-shield-help-pop' );
		if ( ! pop ) {
			return;
		}
		pop.classList.remove( 'qevix-shield-help-pop-flip' );
		var rect = pop.getBoundingClientRect();
		if ( rect.right > document.documentElement.clientWidth - 12 ) {
			pop.classList.add( 'qevix-shield-help-pop-flip' );
		}
	}

	document.addEventListener( 'click', function ( e ) {
		var icon = e.target.closest( '.qevix-shield-help-icon' );
		if ( icon ) {
			e.preventDefault();
			toggle( icon.closest( '.qevix-shield-help' ) );
			return;
		}
		if ( ! e.target.closest( '.qevix-shield-help' ) ) {
			closeAll( null );
		}
	} );

	document.addEventListener( 'keydown', function ( e ) {
		if ( 'Escape' === e.key ) {
			closeAll( null );
			return;
		}
		if ( ( 'Enter' === e.key || ' ' === e.key ) && e.target.classList && e.target.classList.contains( 'qevix-shield-help-icon' ) ) {
			e.preventDefault();
			toggle( e.target.closest( '.qevix-shield-help' ) );
		}
	} );

	// Un-clip tips that open via pure CSS hover/focus too.
	document.addEventListener( 'mouseover', function ( e ) {
		var tip = e.target.closest && e.target.closest( '.qevix-shield-help' );
		if ( tip ) {
			flipIfClipped( tip );
		}
	} );
} )();
