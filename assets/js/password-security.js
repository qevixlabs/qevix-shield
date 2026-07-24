/**
 * Password Security tab: sync each preset <select> with its custom number
 * input, so choosing a preset fills the number box (and choosing "Custom"
 * leaves it for manual entry).
 */
( function () {
	document.querySelectorAll( 'select[data-custom-target]' ).forEach( function ( sel ) {
		var target = document.getElementById( sel.getAttribute( 'data-custom-target' ) );
		if ( ! target ) {
			return;
		}
		sel.addEventListener( 'change', function () {
			if ( 'custom' !== sel.value ) {
				target.value = sel.value;
			}
		} );
	} );
} )();
