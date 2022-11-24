#include "aes192.h"

//TODO
//enhance file interface
//write cleaner ivec xor wrapper function
//read init data + poly from file
//lfsr array -> needed for decryption, solution
//edit helper file
//set/read key from file
//set/read poly + init data (lfsr) from file

AES192::AES192(const uch * data, const ui32& sz, const std::array<uch, keysize_bytes>& key)
: round(0), key(key), dh(std::make_unique<data_handler>(data, sz)), is_encrypted(false), aes_state(true) {
	key_expansion();
	aes_blocks = dh->fetch_aes_blocksz();
	padding = dh->fetch_paddsz();

	ivec = std::make_unique<lfsr_prng>(0xabeaf, 0xacead);
}

AES192::AES192(const uch * data, const ui32& sz, std::array<uch, keysize_bytes>&& key)
: round(0), key(std::move(key)), dh(std::make_unique<data_handler>(data, sz)), is_encrypted(false), aes_state(true) {

	key_expansion();
	aes_blocks = dh->fetch_aes_blocksz();
	padding = dh->fetch_paddsz();

	ivec = std::make_unique<lfsr_prng>(0xabeaf, 0xacead);
}

AES192::AES192(const std::array<uch, keysize_bytes>& key) 
: round(0), key(std::move(key)), dh(std::make_unique<data_handler>()), is_encrypted(false), aes_state(true) {
	key_expansion();
	aes_blocks = dh->fetch_aes_blocksz();
	padding = dh->fetch_paddsz();

	ivec = std::make_unique<lfsr_prng>(0xabeaf, 0xacead);
}

void
AES192::add_block(const uch * data, const ui32& sz) {
	dh->add_data(data, sz);
	aes_blocks = dh->fetch_aes_blocksz();
}

void
AES192::add_block(const std::initializer_list<uch>& data, const ui32& sz) {
	add_block(data.begin(), sz);
}

constexpr uch
AES192::mul2(const uch& val) const {
	//if value >= 128 -> XOR, avoid carry-bit loss
	if (val >= 0x80)
		return (val << 1u) ^ MOD_POLY;
	else
		return val << 1u;
}

uch
AES192::binary_mul(const uch& val, const uch& fact) const {

	/* a := byte in GF(2) field
	 *
	 * Operations:
	 *
	 * 	2a -> 2a, if a < 128
	 * 	2a -> 2a XOR 0x11b if a >= 128
	 * 	3a = 2a XOR a
	 *	...
	 *	...
	 *	9a = a * (8 XOR 1) = 8a XOR a = (2*2*2)a XOR a
	*/

	switch(fact) {
		case 0x2:
			return mul2(val);
		case 0x3:
			return mul2(val) ^ val;
		case 0x9:
			return mul2(mul2(mul2(val))) ^ val;
		case 0xb:
			return mul2(mul2(mul2(val))) ^ mul2(val) ^ val;
		case 0xd:
			return mul2(mul2(mul2(val))) ^ mul2(mul2(val)) ^ val;
		case 0xe:
			return mul2(mul2(mul2(val))) ^ mul2(mul2(val)) ^ mul2(val);
		default:
			return val;
	}
}

void
AES192::sub_bytes() {
	uch r {0}, c {0};
	for ( int x = 0 ; x < AES_BLOCK_BYTES ; ++x) {
		state[r][c] = sbox[state[r][c]];
		c = (c + 1u) % aes_cols_bytes;
		if (!c) ++r;
	}
}

void
AES192::inv_sub_bytes() {
	uch r {0}, c {0};
	for ( int x = 0 ; x < AES_BLOCK_BYTES ; ++x) {
		state[r][c] = sbox_inv[state[r][c]];
		c = (c + 1u) % aes_cols_bytes;
		if (!c) ++r;
	}
}

std::array<uch, 0x4>
AES192::word2arr(const ui32& w) const {
	std::array<uch, 0x4> ret {0};
	ret[0] = ((w & (ui32)0xff000000) >> 0x18);
	ret[1] = ((w & (ui32)0x00ff0000) >> 0x10);
	ret[2] = ((w & (ui32)0x0000ff00) >> 0x08);
	ret[3] = (w & 0xff);
	return ret;
}

ui32
AES192::arr2word(const std::array<uch, 0x4>& a) const {
	ui32 ret {0};
	ret |= (ui32)(a[0] << 0x18);
	ret |= (ui32)(a[1] << 0x10);
	ret |= (ui32)(a[2] << 0x08);
	ret |= a[3];
	return ret;	
}

void
AES192::shift_words() {
	uch x = state[1][0], y, z;
	state[1][0] = state[1][1];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = x;

	x = state[2][0], y = state[2][1];
	state[2][0] = state[2][2];
	state[2][1] = state[2][3];
	state[2][2] = x;
	state[2][3] = y;

	x = state[3][0], y = state[3][1], z = state[3][2];
	state[3][0] = state[3][3];
	state[3][1] = x;
	state[3][2] = y;
	state[3][3] = z;
}

void
AES192::inv_shift_words() {
	uch x = state[1][3], y, z;
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = x;

	x = state[2][2], y = state[2][3];
	state[2][3] = state[2][1];
	state[2][2] = state[2][0];
	state[2][1] = y;
	state[2][0] = x;

	x = state[3][1], y = state[3][2], z = state[3][3];
	state[3][3] = state[3][0];
	state[3][2] = z;
	state[3][1] = y;
	state[3][0] = x;
}

void
AES192::mix_cols() {
	std::array<uch, 0x4> s;
	for ( int x = 0 ; x < aes_cols_bytes ; ++x) {
		s = {state[0][x], state[1][x], state[2][x], state[3][x]};
		state[0][x] =
			binary_mul(s[0], 2) ^
			binary_mul(s[1], 3) ^
			s[2] ^
			s[3];

		state[1][x] =
			binary_mul(s[1], 2) ^
			binary_mul(s[2], 3) ^
			s[0] ^
			s[3];

		state[2][x] = binary_mul(s[2], 2) ^
			binary_mul(s[3], 3) ^
			s[0] ^
			s[1]; 

		state[3][x] = binary_mul(s[0], 3) ^
			binary_mul(s[3], 2) ^
			s[1] ^
			s[2];
	}
}

void
AES192::inv_mix_cols() {
	std::array<uch, 0x4> s;
	for ( int x = 0 ; x < aes_cols_bytes ; ++x) {
		s = {state[0][x], state[1][x], state[2][x], state[3][x]};
		state[0][x] =
			binary_mul(s[0], 0xe) ^
			binary_mul(s[1], 0xb) ^
			binary_mul(s[2], 0xd) ^
			binary_mul(s[3], 0x9);

		state[1][x] =
			binary_mul(s[0], 0x9) ^
			binary_mul(s[1], 0xe) ^
			binary_mul(s[2], 0xb) ^
			binary_mul(s[3], 0xd);

		state[2][x] =
			binary_mul(s[0], 0xd) ^
			binary_mul(s[1], 0x9) ^
			binary_mul(s[2], 0xe) ^
			binary_mul(s[3], 0xb);

		state[3][x] =
			binary_mul(s[0], 0xb) ^
			binary_mul(s[1], 0xd) ^
			binary_mul(s[2], 0x9) ^
			binary_mul(s[3], 0xe);
	}
}

void
AES192::round_key() {
	ui32 w;
	std::array<uch, 0x4> key;
	uch *a, *b, *c, *d;
	for ( int x = 0 ; x < aes_cols_bytes ; ++x) {
		a = &state[0][x], b = &state[1][x],
		c = &state[2][x], d = &state[3][x];
	
		//generate word, XOR with current key, transform, extract
		w = arr2word({*a, *b, *c, *d}) ^ key_schedule[round * aes_cols_bytes + x];
		key = word2arr(w);

		//update reference
		*a = key[0];
		*b = key[1];
		*c = key[2];
		*d = key[3];
	}
}

ui32
AES192::sub_word(const ui32& word) {
	ui32 ret {0};
	uch b = (word & (ui32)0xff000000) >> 0x18;

	ret |= ((ui32)sbox[b] << 0x18);
	
	b = (word & (ui32)0x00ff0000) >> 0x10;
	ret |= ((ui32)sbox[b] << 0x10);

	b = (word & (ui32)0x0000ff00) >> 0x8;
	ret |= ((ui32)sbox[b] << 0x8);

	b = (word & (ui32)0x000000ff);
	ret |= sbox[b];
	return ret;
}

ui32 inline
AES192::rot_word(const ui32& word) {
	return 	((ui32)word << 0x8) | ((word >> 0x18) & 0xff);
}

void
AES192::key_expansion() {
	ui32 word {0}, rcon {0x1000000};
	ui32 idx {0};	
	uch sh {0};

	while (idx < aes_words_bytes) {
		word |= key[(idx << 2)] << 0x18;
		word |= key[(idx << 2) + 1] << 0x10;
		word |= key[(idx << 2) + 2] << 0x08;
		word |= key[(idx << 2) + 3];

		key_schedule[idx++] = word;
		word = 0;
	}

	idx = aes_words_bytes;
	while(idx < (aes_cols_bytes * (AES_ROUNDS + 1))) {
		word = key_schedule[idx - 1];
		if (!(idx % aes_words_bytes)) {
			word = sub_word(rot_word(word)) ^ (rcon << sh++);
		}
		key_schedule[idx] = key_schedule[idx - aes_words_bytes] ^ word;
		++idx;
	}
}

void
AES192::set_aes_state() {
	if (!aes_state) dh->trafo_data2state();
	aes_state = true;
}

void
AES192::unset_aes_state() {
	if (aes_state) dh->trafo_state2data();
	aes_state = false;
}

const
std::vector<std::shared_ptr<aes_block_128bit>>&
AES192::generate_output() const {
	return dh->ret_blocks();
}

//returns bytestream
std::vector<uch>
AES192::ret_bytes() const {
	std::vector<uch> ret;
	const std::vector<std::shared_ptr<aes_block_128bit>>& cont = dh->ret_blocks();
	for ( size_t block = 0 ; block < aes_blocks ; ++block)
		for ( const auto& d2 : cont[block]->ret_block())
			for ( size_t byte = 0 ; byte < aes_cols_bytes ; ++byte)
				ret.emplace_back(d2[byte]);	
	return ret;
}

void
AES192::raw_aes192_encrypt() {

	round = 0;
	round_key();
	++round;

	for ( int x = 1 ; x <= (AES_ROUNDS - 1); ++x, ++round) {
		sub_bytes();	
		shift_words();
		mix_cols();
		round_key();

	}

	sub_bytes();
	shift_words();
	round_key();
}

void
AES192::raw_aes192_decrypt() {

	round = AES_ROUNDS;
	round_key();		
	--round;

	for ( int x = 1 ; x <= (AES_ROUNDS - 1); ++x, --round) {

		inv_shift_words();	
		inv_sub_bytes();
		round_key();
		inv_mix_cols();
	}

	inv_shift_words();
	inv_sub_bytes();
	round_key();
}

void 
AES192::cbc_encrypt() {

 	uch xbyte {0}, r {0} , c {0};
	ui32 cpoly {0};

	//validation
	if (is_encrypted) throw error_handler("STATE already encrypted!");
	if (!dh->is_in_aes_state()) throw error_handler("Not in AES state!");

	//fetch stored blocks
	const std::vector<std::shared_ptr<aes_block_128bit>>& blocks = dh->ret_blocks(); 
	for ( size_t block = 0 ; block < aes_blocks ; ++block) {

		//fetch block from handler struct
		state = blocks[block]->ret_block();
		raw_aes192_encrypt();

		r = c = 0;
		for ( ui16 l = 0; l < AES_BLOCK_BYTES ; ++l ) {
			
			if ( !c ) cpoly = ivec->nxt_period();

			xbyte = (cpoly >> (c << 3)) & 0xff;
			state[r][c] ^= xbyte;

			c = (c + 1u) % 4;
			c ?: ++r;

		}
		blocks[block]->ret_block() = state;
	}
	is_encrypted = true;
}

void 
AES192::cbc_decrypt() {

 	uch xbyte {0}, r {0} , c {0};
	ui32 cpoly { 0};

	//validation
	if (!is_encrypted) throw error_handler("STATE already decrypted!");
	if (!dh->is_in_aes_state()) throw error_handler("Not in AES state!");

	//fetch stored blocks
	const std::vector<std::shared_ptr<aes_block_128bit>>& blocks = dh->ret_blocks(); 

	cpoly = ivec->ret_data();	
	for ( ssize_t block = (aes_blocks - 1u) ; block >= 0; --block) {
		state = blocks[block]->ret_block();

		r = c = 3;
		for ( ui16 l = 0; l < AES_BLOCK_BYTES ; ++l ) {

			xbyte = (cpoly >> (c << 3)) & 0xff;
			state[r][c] ^= xbyte;

			if ( !c-- ) {
				c = 3;
				--r;
				cpoly = ivec->inv_nxt_period();
			}
		}
		raw_aes192_decrypt();
		blocks[block]->ret_block() = state;
	}
	is_encrypted = false;
}
