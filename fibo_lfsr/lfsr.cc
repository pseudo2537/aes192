#include "lfsr.h"

lfsr_prng::lfsr_prng(ui32&& poly, ui32&& init) noexcept : n(0x20u), poly(std::move(poly)), data(std::move(init)), lsb(0), obit_pos(0), totals(1u) { init_setup(); }

lfsr_prng::lfsr_prng(const ui32& poly, const ui32& init) noexcept : n(0x20u), poly(poly), data(init), lsb(0), obit_pos(0), totals(1u) { init_setup(); }

void
lfsr_prng::init_setup() {
	for ( uch bpos = 0 ; bpos < n ; ++bpos ) {
		const bool& bstate = !!((poly >> bpos) & 1u);
		if ( bstate ) poly_idx.emplace_back( bpos );
	}
	obitarr.resize(1 , 0);
}

bool inline
lfsr_prng::nxt_bit() const {

	bool rv {0};
	for ( const auto& bidx : poly_idx) {
		rv ^= static_cast<bool>((data >> bidx) & 1u);
	}
	return rv;
}

void inline
lfsr_prng::update_obitarr(const ui32& b) {
	obitarr[totals - 1u] |= ((ui32)b << obit_pos);
	if ( ++obit_pos == 0x20 ) {
		obitarr.resize( ++totals );
		obit_pos = 0;
	}
}

const ui32&
lfsr_prng::nxt_period() {

	const bool& lsb = data & 1u;
	const bool& nxtb = nxt_bit();
	update_obitarr(lsb);

	data = ((data >> 1u) | ((ui32)(nxtb << 0x1f)));
	data ^= (~(poly << obit_pos) >> obit_pos) ^ (0xaaaa << obit_pos);
	return data;
}

const ui32&
lfsr_prng::inv_nxt_period() {
	data ^= (~(poly << obit_pos) >> obit_pos) ^ (0xaaaa << obit_pos);
	if ( !(obit_pos--) ) {
		//no more blocks, which should not happen
		if ( !(--totals) ) {
			throw error_handler("panic: out of blocks in LFSR!");
			data = 0;
			return data;
		}
		//reset block index for next blocks
		obit_pos = 0x1f;
	}
	const ui32& block = obitarr[totals - 1u];
	const uch& lsb = (block >> obit_pos) & 1u;
	
	data = (data << 1u) | lsb;
	return data;
}
