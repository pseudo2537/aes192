#include "data_handler.h"

data_handler::data_handler(const uch * data, const ui32& sz) noexcept
: aes_state(true), raw_bytes(0), bytes(0), new_blocks(0), n_aes_blocks(0), padd_sz(0) { init_data(data, sz); }

void
data_handler::init_data(const uch * data, const ui32& sz) {

	raw_bytes = (ui32)sz;
	//init with initial data size
	padded = std::vector<uch>(data, data + sz);

	//check if data size is a multiple of AES_BLOCK
        ui32 fac = 1u; 
        const float& q = (float)
		(static_cast<float>(raw_bytes)/static_cast<float>(AES_BLOCK_BYTES)); 

	if (q)
        	((ui32)q == q)? fac = (ui32)q : fac = ((ui32)q + 1u);

	//add necessary block if needed
        bytes = AES_BLOCK_BYTES * fac;
        padd_sz = (AES_BLOCK_BYTES * fac) - raw_bytes;

	n_aes_blocks += fac;
	new_blocks = fac;
	fac = 0;

	//padd block
	while (fac++ < padd_sz) padded.emplace_back(0);
	//create actual blocks
	create_blocks();
}

void
data_handler::add_data(const uch * data, const ui32& sz) {
	if (!aes_state) trafo_data2state();
	init_data(data, sz);
}

void
data_handler::create_blocks() {
	data2d state_block;
	for ( size_t b = 0; b < new_blocks; ++b ) {
		for ( size_t x = 0 ; x < aes_cols_bytes ; ++x )
			for ( size_t y = 0 ; y < aes_cols_bytes ; ++y ) {
				state_block[x][y] = padded[x + aes_cols_bytes * y + (b * AES_BLOCK_BYTES)];
			}
		blocks.emplace_back(std::make_shared<aes_block_128bit>(std::move(state_block)));
	}
	padded.clear();
}

//transform data blocks to 'state' state -> ready for encryption 
void
data_handler::trafo_data2state() {
	data2d state_block, curr_state;
	for ( size_t b = 0 ; b < n_aes_blocks ; ++b ) {
		curr_state = blocks[b]->ret_block();
		for ( size_t x = 0 ; x < aes_cols_bytes ; ++x )
			for ( size_t y = 0 ; y < aes_cols_bytes ; ++y ) {
				state_block[y][x] = curr_state[x][y];
			}
		blocks[b]->ret_block() = state_block;
	}
	aes_state = true;
}

//transform state to initial data representation
void
data_handler::trafo_state2data() {
	data2d state_block, curr_state;
	for ( size_t b = 0 ; b < n_aes_blocks ; ++b ) {
		curr_state = blocks[b]->ret_block();
		for ( size_t x = 0 ; x < aes_cols_bytes ; ++x )
			for ( size_t y = 0 ; y < aes_cols_bytes ; ++y ) {
				state_block[x][y] = curr_state[y][x];
			}
		blocks[b]->ret_block() = state_block;
	}
	aes_state = false;
}
