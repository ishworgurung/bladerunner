// Package detect holds the control-plane analytics: attack-state detection,
// fingerprint generation and heavy-hitter selection. It is pure logic with no
// kernel dependency, so it is unit-testable anywhere.
//
// This package is deliberately free of kernel and I/O dependencies (it only
// imports the shared Sample type), so every decision it makes can be unit-tested
// with synthetic numbers on any machine.
package detect

import "time"

// Detector tracks an EWMA baseline of offered load (pps, counting packets
// that were dropped too) and flips into attack mode with hysteresis.
type Detector struct {
	Alpha         float64       // EWMA weight of the newest sample (0..1)
	TriggerFactor float64       // attack when pps > baseline * factor ...
	MinPPS        float64       // ... and pps > MinPPS (absolute floor)
	ReleaseAfter  time.Duration // pps must stay below release level this long

	baseline   float64
	init       bool
	attack     bool
	belowSince time.Time
}

// Baseline returns the current learned baseline.
func (d *Detector) Baseline() float64 { return d.baseline }

// Attack reports the current state.
func (d *Detector) Attack() bool { return d.attack }

// trigger is the rate above which we call it an attack: a multiple of the learned
// baseline, but never lower than the absolute MinPPS floor (so a quiet site with a
// tiny baseline does not trip on ordinary bursts).
func (d *Detector) trigger() float64 {
	t := d.baseline * d.TriggerFactor
	if t < d.MinPPS {
		t = d.MinPPS
	}
	return t
}

// Update feeds one measurement. changed is true on a state transition.
// The baseline is frozen while under attack so the attack cannot teach it.
func (d *Detector) Update(pps float64, now time.Time) (attack, changed bool) {
	// The very first sample seeds the baseline; we cannot judge a change without a reference.
	if !d.init {
		d.baseline, d.init = pps, true
		return false, false
	}
	// NORMAL state: look for a spike, otherwise keep learning.
	if !d.attack {
		// Spike above the trigger: enter attack mode and stop learning.
		if pps > d.trigger() {
			d.attack, d.belowSince = true, time.Time{}
			return true, true
		}
		// Exponentially-weighted moving average. Small Alpha = slow, stable baseline that
		// a short burst cannot drag upward.
		d.baseline = d.Alpha*pps + (1-d.Alpha)*d.baseline
		return false, false
	}
	// ATTACK state: leave only after the rate has stayed below 70% of the trigger for
	// ReleaseAfter. The 30% gap (hysteresis) plus the hold time stop flapping when the
	// attack rate hovers around the threshold.
	if pps < d.trigger()*0.7 {
		if d.belowSince.IsZero() {
			d.belowSince = now
		}
		// Quiet long enough: return to normal. The baseline was frozen throughout, so it still describes pre-attack traffic.
		if now.Sub(d.belowSince) >= d.ReleaseAfter {
			d.attack, d.belowSince = false, time.Time{}
			return false, true
		}
		// Any noisy sample resets the quiet timer.
	} else {
		d.belowSince = time.Time{}
	}
	return d.attack, false
}
