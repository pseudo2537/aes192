#ifndef __FILE_READER__
#define __FILE_READER__

#include "helper.h"

class file_reader {

	ui64 file_sz;
	std::vector<uch> cont;

public:
	file_reader() = delete;
	file_reader(const char * const fname);

	const std::vector<uch>& fetch_content() const { return cont; }
	const uch * raw_fetch_content() const { return cont.data(); }

	const ui64& ret_file_sz() const { return file_sz; }
};

#endif
