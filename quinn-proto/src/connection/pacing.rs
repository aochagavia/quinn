//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

pub(super) struct Pacer {
    rtt_pacer: RttPacer,
    rate_limited_pacer: Option<RateLimitedPacer>,
}

impl Pacer {
    pub(super) fn get_max_bytes_per_second(&self) -> Option<u64> {
        self.rate_limited_pacer.as_ref().map(|p| p.capacity)
    }

    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, max_bytes_per_second: Option<u64>, now: Instant) -> Self {
        Self {
            rtt_pacer: RttPacer::new(smoothed_rtt, window, mtu, now),
            rate_limited_pacer: max_bytes_per_second.map(|x| RateLimitedPacer::new(x, now)),
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.rtt_pacer.on_transmit(packet_length);
        if let Some(pacer) = &mut self.rate_limited_pacer {
            pacer.on_transmit(packet_length)
        }
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        let rtt_pacer_delay = self.rtt_pacer.delay(smoothed_rtt, bytes_to_send, mtu, window, now);
        let rate_limited_pacer_delay = self.rate_limited_pacer.as_mut().and_then(|pacer| pacer.delay(bytes_to_send, now));

        match (rtt_pacer_delay, rate_limited_pacer_delay) {
            (Some(rtt_pacer_delay), Some(rate_limited_pacer_delay)) =>
                Some(rtt_pacer_delay.max(rate_limited_pacer_delay)),
            _ => rtt_pacer_delay.or(rate_limited_pacer_delay)
        }
    }
}

struct RateLimitedPacer {
    capacity: u64,
    tokens: u64,
    prev: Instant,
}

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived from the specified throughput (in bytes per
/// second). Capacity equals the number of bytes that may be sent in a second.
///
/// The bucket refills at the specified rate (e.g. if 100 bytes can be sent per
/// second, the bucket refills 100 bytes per second)
impl RateLimitedPacer {
    /// Obtains a new [`RateLimitedPacer`].
    fn new(max_bytes_per_second: u64, now: Instant) -> Self {
        Self {
            capacity: max_bytes_per_second,
            tokens: max_bytes_per_second,
            prev: now
        }
    }

    /// Record that a packet has been transmitted.
    fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    fn delay(
        &mut self,
        bytes_to_send: u64,
        now: Instant,
    ) -> Option<Instant> {
        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let elapsed = now.saturating_duration_since(self.prev);
        let token_refill_rate_per_second = self.capacity as f64;
        let new_tokens = (token_refill_rate_per_second * elapsed.as_secs_f64()).round() as u64;
        self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);

        // In the unlikely event that we're getting polled faster than tokens are generated, ensure
        // that `elapsed` can grow until we make progress.
        if new_tokens > 0 {
            self.prev = now;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // Sanity check
        assert!(bytes_to_send <= self.capacity);

        let missing_tokens = bytes_to_send - self.tokens;
        let seconds_until_enough_tokens = missing_tokens as f64 / token_refill_rate_per_second;
        Some(now + Duration::from_secs_f64(seconds_until_enough_tokens))
    }
}

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
struct RttPacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
}

impl RttPacer {
    /// Obtains a new [`RttPacer`].
    fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
                .is_none()
        );
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, None, old_instant);
        let packet_capacity = pacer.rtt_pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.rtt_pacer.tokens, pacer.rtt_pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.rtt_pacer.tokens, pacer.rtt_pacer.capacity);
    }

    #[test]
    fn computes_pause_correctly_for_rate_limited() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, Some(2_000), old_instant);
        for _ in 0..2 {
            assert_eq!(
                pacer.delay(rtt, 1_000, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let actual_delay = pacer
            .delay(rtt, 1_000, mtu, window, old_instant)
            .expect("Send must be delayed")
            .duration_since(old_instant);

        let expected_delay = Duration::from_millis(500);
        let diff = actual_delay.abs_diff(expected_delay);

        // Allow up to 2ns difference due to rounding
        assert!(
            diff < Duration::from_nanos(2),
            "expected ≈ {expected_delay:?}, got {actual_delay:?} (diff {diff:?})"
        );

        // Should be able to send after a while
        let now = old_instant + expected_delay / 2;
        assert_eq!(
            pacer.delay(
                rtt,
                500,
                mtu,
                window,
                now
            ),
            None
        );
    }
}
