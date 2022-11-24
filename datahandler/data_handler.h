#ifndef __DATA_HANDLER__
#define __DATA_HANDLER__

#include "./../helper.h"

struct aes_block_128bit {

	aes_block_128bit(data2d&& block) noexcept
	: data(std::move(block)) { }

	data2d& ret_block() { return data; }
private:
	data2d data;
};

class data_handler {

	bool aes_state;
	
	//attributes are reused on 'add_data' call
	ui32
		raw_bytes,
		bytes,
		new_blocks;
	
	ui32 n_aes_blocks;
	
	uch padd_sz;
	void create_blocks();

	std::vector<uch> padded;
	std::vector<std::shared_ptr<aes_block_128bit>> blocks;

public:
	data_handler();
	data_handler(const uch *, const ui32&) noexcept;

	//overload containers
	template<typename T>
	data_handler(const T& cont)
	: data_handler(cont.data(), cont.size()) {}

	void init_data(const uch *, const ui32&);
	void add_data(const uch *, const ui32&);

	const std::vector<std::shared_ptr<aes_block_128bit>>& ret_blocks() const { return blocks; }

	void trafo_data2state();
	void trafo_state2data();

	const uch& fetch_paddsz() const { return padd_sz; }
	const ui32& fetch_aes_blocksz() const { return n_aes_blocks; }
	const bool& is_in_aes_state() const { return aes_state; }
};

#endif
