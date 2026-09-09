package sphincsminus

import "encoding/binary"

// field extracts a width-bit (width in [0,64]) field starting at bit
// lsbOffset of the 256-bit big-endian value in d, counting bit positions
// LSB-first from the least-significant bit of the integer d represents
// (SPEC §7): bit 0 is the least-significant bit of d[31], bit 255 is the
// most-significant bit of d[0]. Fields may straddle byte boundaries.
//
// width must be <= 64; every caller in this package passes a width
// derived from *Params (a, h, or log_w), all of which are well under that
// bound, so this is an internal-invariant check, not adversarial-input
// handling.
func field(d *word, lsbOffset, width uint) uint64 {
	if width == 0 {
		return 0
	}
	if width > 64 {
		panic("sphincsminus: field width must be <= 64")
	}

	// View d as four 64-bit little-endian "limbs" (limb 0 = the least
	// significant 64 bits, i.e. d[24:32] read big-endian; limb 3 = the
	// most significant 64 bits, d[0:8]).
	limbs := [4]uint64{
		binary.BigEndian.Uint64(d[24:32]),
		binary.BigEndian.Uint64(d[16:24]),
		binary.BigEndian.Uint64(d[8:16]),
		binary.BigEndian.Uint64(d[0:8]),
	}

	startLimb := lsbOffset / 64
	bitShift := lsbOffset % 64

	var lo, hi uint64
	if startLimb < 4 {
		lo = limbs[startLimb]
	}
	if startLimb+1 < 4 {
		hi = limbs[startLimb+1]
	}

	v := lo >> bitShift
	if bitShift != 0 {
		v |= hi << (64 - bitShift)
	}

	mask := (uint64(1) << width) - 1 // width==64 wraps 1<<64 to 0, giving mask=^uint64(0), correct.
	return v & mask
}

// forsIndices returns the k FORS+C leaf indices parsed LSB-first from the
// message digest: forsIdx[i] = (digest >> (i*a)) & (2^a - 1) (SPEC §7).
func forsIndices(d *word, p *Params) []uint32 {
	idx := make([]uint32, p.K)
	for i := 0; i < p.K; i++ {
		idx[i] = uint32(field(d, uint(i*p.A), uint(p.A)))
	}
	return idx
}

// htIndex returns the h-bit hypertree leaf index parsed from the message
// digest immediately after the k FORS indices: htIdx = (digest >> (k*a)) &
// (2^h - 1) (SPEC §7).
func htIndex(d *word, p *Params) uint32 {
	return uint32(field(d, uint(p.K*p.A), uint(p.H)))
}

// wotsDigits returns the l=43 base-w WOTS+C digits parsed LSB-first from a
// WotsDigest output D: digit[i] = (D >> (log_w*i)) & (w-1) (SPEC §9).
func wotsDigits(d *word, p *Params) [43]uint8 {
	var digits [43]uint8
	for i := 0; i < p.L; i++ {
		digits[i] = uint8(field(d, uint(i*p.LogW), uint(p.LogW)))
	}
	return digits
}

// digitSum sums the 43 WOTS+C digits; a valid signature requires this to
// equal Params.TargetSum (SPEC §9).
func digitSum(digits [43]uint8) uint32 {
	var sum uint32
	for _, x := range digits {
		sum += uint32(x)
	}
	return sum
}
