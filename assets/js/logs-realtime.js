/**
 * Realtime audit-log polling for the Qevix Shield Logs screen.
 *
 * Every `interval` ms it POSTs to admin-ajax (action qevix_shield_poll_logs) for
 * rows newer than the highest id currently in the table, prepends them on top,
 * and flashes each new row green. Polling pauses while the browser tab is
 * hidden. All cell values are written with textContent — no HTML is injected
 * from the server response.
 */
( function () {
	'use strict';

	if ( typeof window.QevixShieldLogs === 'undefined' ) {
		return;
	}

	var config = window.QevixShieldLogs;
	var tbody  = document.getElementById( 'qevix-shield-logs-body' );
	if ( ! tbody ) {
		return;
	}

	var indicator = document.getElementById( 'qevix-shield-live-indicator' );
	var timer     = null;
	var inFlight  = false;

	// Column order must match views/logs.php:
	// Time, User, IP, Browser, Action, Module, Severity, Status.
	var COLUMNS = [ 'timestamp', 'username', 'ip', 'browser', 'action', 'module', 'severity', 'status' ];

	function highestId() {
		var max = 0;
		var rows = tbody.querySelectorAll( 'tr[data-log-id]' );
		for ( var i = 0; i < rows.length; i++ ) {
			var id = parseInt( rows[ i ].getAttribute( 'data-log-id' ), 10 );
			if ( id > max ) {
				max = id;
			}
		}
		return max;
	}

	function buildRow( row ) {
		var tr = document.createElement( 'tr' );
		tr.setAttribute( 'data-log-id', String( row.id ) );
		tr.className = 'qevix-shield-row-new';
		for ( var c = 0; c < COLUMNS.length; c++ ) {
			var td = document.createElement( 'td' );
			td.textContent = row[ COLUMNS[ c ] ] != null ? String( row[ COLUMNS[ c ] ] ) : '';
			tr.appendChild( td );
		}
		return tr;
	}

	function prependRows( rows ) {
		// Drop the "no entries" placeholder if it is showing.
		var empty = tbody.querySelector( '.qevix-shield-logs-empty' );
		if ( empty ) {
			empty.parentNode.removeChild( empty );
		}

		// Server returns newest first; a fragment in that same order inserted
		// before the first child keeps the table in descending order.
		var frag = document.createDocumentFragment();
		for ( var i = 0; i < rows.length; i++ ) {
			frag.appendChild( buildRow( rows[ i ] ) );
		}
		tbody.insertBefore( frag, tbody.firstChild );

		if ( indicator ) {
			indicator.classList.add( 'qevix-shield-live-pulse' );
			window.setTimeout( function () {
				indicator.classList.remove( 'qevix-shield-live-pulse' );
			}, 1200 );
		}
	}

	function poll() {
		if ( inFlight || document.hidden ) {
			return;
		}
		inFlight = true;

		var body = new URLSearchParams();
		body.set( 'action', 'qevix_shield_poll_logs' );
		body.set( 'nonce', config.nonce );
		body.set( 'after_id', String( highestId() ) );
		if ( config.filters ) {
			Object.keys( config.filters ).forEach( function ( key ) {
				body.set( key, config.filters[ key ] );
			} );
		}

		window.fetch( config.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		} ).then( function ( res ) {
			return res.json();
		} ).then( function ( json ) {
			if ( json && json.success && json.data && json.data.rows && json.data.rows.length ) {
				prependRows( json.data.rows );
			}
		} ).catch( function () {
			// Network hiccup — swallow and retry on the next tick.
		} ).then( function () {
			inFlight = false;
		} );
	}

	function start() {
		if ( timer ) {
			return;
		}
		timer = window.setInterval( poll, config.interval || 10000 );
	}

	function stop() {
		if ( timer ) {
			window.clearInterval( timer );
			timer = null;
		}
	}

	document.addEventListener( 'visibilitychange', function () {
		if ( document.hidden ) {
			stop();
		} else {
			start();
			poll(); // Catch up immediately on return.
		}
	} );

	start();
} )();
