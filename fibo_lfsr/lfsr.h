#ifndef __LFSR_PRNG__
#define __LFSR_PRNG__

#include "../helper.h"

class lfsr_prng {
	
	const ui16 n;
	const ui32 poly;
	//current data, in any evolution
	ui32 cdata;

public:
	lfsr_prng() = delete;			
	explicit lfsr_prng(ui32&&, ui32&&) noexcept;
	lfsr_prng(const ui32&, const ui32&) noexcept;

	const ui32& nxt_period();
	const ui32& inv_nxt_period();

	ui32 ret_data() const { return cdata; }
};

#endif
