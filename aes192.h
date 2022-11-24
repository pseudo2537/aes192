#ifndef __AES192__
#define __AES192__

#include "fibo_lfsr/lfsr.h"
#include "datahandler/data_handler.h"

class AES192 {

	uch round;
	const std::array<uch, keysize_bytes>& key;

	std::unique_ptr<data_handler> dh;

	bool is_encrypted;
	bool aes_state;

	ui32 aes_blocks;
	uch padding;

	//modified ivec
	std::unique_ptr<lfsr_prng> ivec;

	data2d state;
	std::array<ui32, 0x34> key_schedule {0};

	uch lrot_uchar(const uch& c, const int& n = 1) const { return (c << n) | (c >> (8 - n)); }
	uch rrot_uchar(const uch& c, const int& n = 1) const { return (c >> n) | (c << (8 - n)); }

	void sub_bytes();	
	void shift_words();
	void mix_cols();

	void inv_mix_cols();
	void inv_shift_words();
	void inv_sub_bytes();	

	void key_expansion();
	void round_key();

	void raw_aes192_encrypt();
	void raw_aes192_decrypt();

	std::array<uch, 0x4> word2arr(const ui32&) const;
	ui32 arr2word(const std::array<uch, 4>&) const;

	ui32 sub_word(const ui32&);
	ui32 rot_word(const ui32&);

	constexpr uch mul2(const uch&) const;
	uch binary_mul(const uch&, const uch&) const;

public:
	AES192() = delete;

	AES192(const uch * data, const ui32&, const std::array<uch, keysize_bytes>&); 
	explicit AES192(const uch * data, const ui32&, std::array<uch, keysize_bytes>&&); 

	AES192(const std::array<uch, keysize_bytes>&);

	void cbc_encrypt();
	void cbc_decrypt();

	const bool& is_in_aes_state() const { return dh->is_in_aes_state(); }

	void set_aes_state();
	void unset_aes_state();

	const std::vector<std::shared_ptr<aes_block_128bit>>& generate_output() const;

	//returns bytestream
	std::vector<uch> ret_bytes() const;

	void add_block(const uch *, const ui32&);
	void add_block(const std::initializer_list<uch>& data, const ui32&);

	//number of blocks
	ui32 fetch_blocks() const { return aes_blocks; }

};

#endif
