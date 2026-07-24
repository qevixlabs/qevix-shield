<?php
/**
 * Email notification channel. Critical-severity events email the admin
 * recipients in the free tier (opt-in — OFF by default under the 2026-07-13
 * neutral-activation policy; the admin enables it on the Notifications tab).
 * SMS/webhook/
 * Slack/Discord channels and per-event/severity-threshold configuration are
 * a pro feature, hanging off the same `qevix_shield_after_log` action this
 * class listens on.
 *
 * Delivery is BATCHED, not per-event: one security incident (a brute-force
 * wave, a scanner sweep) can log dozens of critical events in minutes, and
 * emailing each one separately both floods the recipients and looks like
 * outbound spam to mail providers. The first critical event in a quiet
 * period opens a short collection window; everything that lands inside it
 * joins the same queue, and ONE summary email goes out when the window
 * closes.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QevixShield_Alerts {

	/** Option holding the pending batch: array{events: array[], overflow: int}. Autoload off. */
	const QUEUE_OPTION = 'qevix_shield_alert_queue';

	/**
	 * Collection window in seconds: how long the first event of a batch waits
	 * so followers can join its email. Filterable via
	 * `qevix_shield_alert_batch_window`; floored at 30s so the send can't be
	 * scheduled into the same request storm that's generating the events.
	 */
	const BATCH_WINDOW = 120;

	/** Events listed per email; anything beyond only bumps the "+N more" line. */
	const QUEUE_MAX = 100;

	/** @var QevixShield_Settings */
	private $settings;

	public function __construct( QevixShield_Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Hooked on qevix_shield_after_log — runs inline inside QevixShield_Audit_Log::log(),
	 * i.e. on the very request being audited (a failed login, a firewall block).
	 *
	 * So this does NOT send mail here: wp_mail() is a blocking SMTP round-trip
	 * that would add latency to every critical-severity event on the hot path.
	 * It only appends the event to the pending batch and makes sure ONE
	 * deferred send is scheduled; the email goes out in dispatch_alert() when
	 * the batch window closes.
	 */
	public function maybe_notify( array $logEntry ) {
		if ( 'critical' !== $logEntry['severity'] ) {
			return;
		}

		// Opt-in (default OFF, neutral-activation policy 2026-07-13): nothing
		// emails until the admin enables the channel on the Notifications tab.
		if ( ! $this->settings->get( 'alerts_enabled', false ) ) {
			return;
		}

		// Only the fields the email renders — a small, serializable payload.
		// Recipients are resolved at send time (dispatch_alert) so they
		// reflect settings as of when the mail actually goes out.
		$payload = array(
			'action'    => isset( $logEntry['action'] ) ? (string) $logEntry['action'] : '',
			'ip'        => isset( $logEntry['ip'] ) ? (string) $logEntry['ip'] : '',
			'username'  => isset( $logEntry['username'] ) ? (string) $logEntry['username'] : '',
			'timestamp' => isset( $logEntry['timestamp'] ) ? (string) $logEntry['timestamp'] : '',
		);

		$queue = get_option( self::QUEUE_OPTION, array() );
		if ( ! isset( $queue['events'] ) || ! is_array( $queue['events'] ) ) {
			$queue = array(
				'events'   => array(),
				'overflow' => 0,
			);
		}
		if ( count( $queue['events'] ) < self::QUEUE_MAX ) {
			$queue['events'][] = $payload;
		} else {
			$queue['overflow'] = (int) $queue['overflow'] + 1;
		}
		update_option( self::QUEUE_OPTION, $queue, false );

		// One pending send at a time: the first event of a quiet period opens
		// the window; followers just join the queue above.
		if ( ! wp_next_scheduled( 'qevix_shield_send_alert' ) ) {
			$window = max( 30, (int) apply_filters( 'qevix_shield_alert_batch_window', self::BATCH_WINDOW ) );
			wp_schedule_single_event( time() + $window, 'qevix_shield_send_alert' );
		}
	}

	/**
	 * Hooked on qevix_shield_send_alert (the deferred cron event scheduled by
	 * maybe_notify). Drains the batch queue and sends ONE summary email off
	 * the audited request. (Param-less on purpose: a leftover pre-batching
	 * event that still carries a payload arg is simply ignored.)
	 */
	public function dispatch_alert() {
		$queue = get_option( self::QUEUE_OPTION, array() );
		delete_option( self::QUEUE_OPTION );

		// Re-check at send time: the setting may have been switched off between
		// the window opening and it closing (the queue is dropped either way).
		if ( ! $this->settings->get( 'alerts_enabled', false ) ) {
			return;
		}

		$events = ( isset( $queue['events'] ) && is_array( $queue['events'] ) ) ? $queue['events'] : array();
		if ( empty( $events ) ) {
			return;
		}
		$overflow = isset( $queue['overflow'] ) ? (int) $queue['overflow'] : 0;
		$total    = count( $events ) + $overflow;

		// Recipients are the administrative emails configured on the
		// Notifications tab (multiple supported); defaults to the WP admin email.
		$recipients = $this->settings->get_admin_emails();
		if ( empty( $recipients ) ) {
			return;
		}

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		$subject = sprintf(
			/* translators: 1: site name, 2: number of events */
			_n( '[%1$s] Qevix Shield security alert (%2$d critical event)', '[%1$s] Qevix Shield security alert (%2$d critical events)', $total, 'qevix-shield' ),
			$site,
			$total
		);

		$lines = array();
		foreach ( $events as $event ) {
			$username = ( isset( $event['username'] ) && '' !== $event['username'] )
				? $event['username']
				: __( '(unknown)', 'qevix-shield' );
			$lines[]  = sprintf(
				/* translators: 1: action, 2: ip, 3: username, 4: timestamp */
				__( '- %1$s — IP %2$s, user %3$s, at %4$s', 'qevix-shield' ),
				isset( $event['action'] ) ? $event['action'] : '',
				isset( $event['ip'] ) ? $event['ip'] : '',
				$username,
				isset( $event['timestamp'] ) ? $event['timestamp'] : ''
			);
		}
		if ( $overflow > 0 ) {
			$lines[] = sprintf(
				/* translators: %d: number of additional events not listed */
				_n( '…and %d more event not listed here.', '…and %d more events not listed here.', $overflow, 'qevix-shield' ),
				$overflow
			);
		}

		$logsUrl = admin_url( 'admin.php?page=qevix-shield-logs' );
		$intro   = sprintf(
			/* translators: %d: number of events */
			_n( '%d critical security event was detected:', '%d critical security events were detected:', $total, 'qevix-shield' ),
			$total
		);

		// Plain-text alternative (AltBody) — also the fallback for text-only clients.
		$plaintext = $intro . "\n\n" . implode( "\n", $lines ) . "\n\n" . sprintf(
			/* translators: %s: admin URL of the Qevix Shield logs screen */
			__( 'Full details: %s', 'qevix-shield' ),
			$logsUrl
		);

		// HTML body (shared template).
		$rows = '';
		foreach ( $events as $event ) {
			$username = ( isset( $event['username'] ) && '' !== $event['username'] ) ? $event['username'] : __( '(unknown)', 'qevix-shield' );
			$rows    .= '<tr><td style="padding:9px 0;border-bottom:1px solid #f0f0f1;font-size:13px;line-height:1.5;color:#3c434a;">'
				. '<strong style="color:#1d2327;">' . esc_html( isset( $event['action'] ) ? $event['action'] : '' ) . '</strong>'
				. '<span style="color:#646970;"> — ' . esc_html__( 'IP', 'qevix-shield' ) . ' ' . esc_html( isset( $event['ip'] ) ? $event['ip'] : '' )
				. ' · ' . esc_html( $username ) . ' · ' . esc_html( isset( $event['timestamp'] ) ? $event['timestamp'] : '' )
				. '</span></td></tr>';
		}
		$overflowHtml = '';
		if ( $overflow > 0 ) {
			$overflowHtml = '<p style="margin:12px 0 0;font-size:12px;color:#646970;">' . esc_html( sprintf(
				/* translators: %d: number of additional events not listed */
				_n( '…and %d more event not listed here.', '…and %d more events not listed here.', $overflow, 'qevix-shield' ),
				$overflow
			) ) . '</p>';
		}
		$inner = '<p style="margin:0 0 16px;font-size:14px;line-height:1.6;color:#3c434a;">' . esc_html( $intro ) . '</p>'
			. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">' . $rows . '</table>'
			. $overflowHtml
			. '<p style="margin:22px 0 0;"><a href="' . esc_url( $logsUrl ) . '" style="display:inline-block;background:#2271b1;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 18px;border-radius:6px;">'
			. esc_html__( 'View full log', 'qevix-shield' ) . '</a></p>';

		$html = QevixShield_Util::email_wrap( __( 'Security alert', 'qevix-shield' ), $inner );
		$sent = QevixShield_Util::send_html_mail( $recipients, $subject, $html, $plaintext );

		// A rejected hand-off must not vanish: the admin believes critical
		// events email out. wp_mail() only reports the local hand-off (later
		// SMTP bounces are invisible to PHP), but even that signal is worth a
		// log row. Warning severity — a critical row would re-queue another
		// doomed email about the email being broken; pro's SMS/webhook
		// channels can still pick the warning up and deliver it another way.
		if ( ! $sent ) {
			QevixShield_Audit_Log::log(
				array(
					'action'   => 'alert_email_failed',
					'severity' => 'warning',
					'module'   => 'qevix-shield',
					'status'   => 'failed',
					'user_id'  => 0,
				)
			);
		}
	}
}
