#include "readfile.h"

file_reader::file_reader(const char * const fname) {

	uch byte;
	ui64 fpos {0};
	std::ifstream file(fname, std::ios::binary);
	if (!file.is_open()) {
		throw error_handler("opening file!");
	}

	while (!file.eof()) {
		cont.emplace_back(byte);
		++fpos;
		byte = file.get();
	}
	file_sz = fpos;
}
