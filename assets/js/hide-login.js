/**
 * Hide Login tab: reveal the "Custom URL" input only when the Custom redirect
 * mode is selected. The typed URL is kept when switching away — the save
 * handler ignores it for non-custom modes, so wiping it here would lose the
 * value if the user toggles back before saving.
 */
( function () {
	var input = document.getElementById( 'qevix-shield-redirect-custom-url' );
	if ( ! input ) {
		return;
	}
	var radios = document.querySelectorAll( 'input[name="redirect_mode"]' );
	radios.forEach( function ( radio ) {
		radio.addEventListener( 'change', function () {
			var isCustom = 'custom' === this.value;
			input.hidden = ! isCustom;
			if ( isCustom ) {
				input.focus();
			}
		} );
	} );
} )();
