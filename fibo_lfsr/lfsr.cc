#include "lfsr.h"

lfsr_prng::lfsr_prng(ui32&& poly, ui32&& cinit) noexcept : n(0x20u), poly(std::move(poly)), cdata(std::move(cinit)) {}
lfsr_prng::lfsr_prng(const ui32& poly, const ui32& cinit) noexcept : n(0x20u), poly(poly), cdata(cinit) {}

const ui32&
lfsr_prng::nxt_period() {
	const ui32& nxtb = cdata & 1u;
	cdata = (cdata >> 1u) ^ ((ui32)(nxtb << 0x1f));
	const ui32& head = (cdata & (0xf << 0x1c));
	cdata ^= (poly >> head);
	return cdata;
}

const ui32&
lfsr_prng::inv_nxt_period() {
	const ui32& head = (cdata & (0xf << 0x1c));
	cdata ^= (poly >> head);
	const ui32& lsb = cdata >> 0x1f;
	cdata = (cdata << 1u) ^ lsb;
	return cdata;
}
