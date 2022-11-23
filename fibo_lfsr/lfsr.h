#ifndef __LFSR_PRNG__
#define __LFSR_PRNG__

#include "../helper.h"

class lfsr_prng {
	
	const ui16 n;
	const ui32 poly;
	ui32 data;

	bool lsb;	

	//bit pos in a ui32 block
	ui32 obit_pos;
	//total nr of ui32 blocks
	ui32 totals;
	//output bit array
	std::vector<ui32> obitarr;
	std::vector<uch> poly_idx;

	bool nxt_bit() const;
	void update_obitarr(const ui32&);
	void init_setup();
public:
	lfsr_prng() = delete;			
	explicit lfsr_prng(ui32&&, ui32&&) noexcept;
	lfsr_prng(const ui32&, const ui32&) noexcept;

	const ui32& nxt_period();
	const ui32& inv_nxt_period();

	ui32 ret_data() const { return data; }
};

#endif
