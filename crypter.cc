#include "aes192.h"

//debug function
//more info on data2d in './herlper.h'
void
printblock(data2d& b) {
        for ( int x = 0 ; x < aes_cols_bytes ; ++x) {
                for ( int y = 0 ; y < aes_cols_bytes ; ++y) {
                        std::cout << std::hex << (unsigned int)b[x][y] << " ";
                }
        }
        std::cout << std::endl;
}

int main() {

	AES192 crypter(aes_key);
	//AES192 crypter(container.data(), container.size(), aes_key);

	const unsigned int arr_sz = 4;
	std::array<unsigned char, arr_sz> data0 = {0x11, 0x22, 0x33, 0x44};

	try {
		//in 'aes state'
		//add data with containers 
		crypter.add_block(data0.data(), arr_sz);
		//add data with initialization vector
		crypter.add_block({0x55, 0x66, 0x77}, 3);
		crypter.add_block({0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6}, 18);

		const unsigned int& aes_blocks = crypter.fetch_blocks();

		//unset 'aes state'
		crypter.unset_aes_state();	

		std::cout << std::endl << "Data before encryption [" << (unsigned int)aes_blocks << " blocks]\n" << std::endl;

		const auto& states0 = crypter.generate_output();
		for ( const auto& block : states0 )
			printblock(block->ret_block());			

		//'aes state' needed for encryption
		crypter.set_aes_state();
		crypter.cbc_encrypt();	

		crypter.unset_aes_state();	

		std::cout << std::endl << "Data after encryption [" << (unsigned int)aes_blocks << " blocks]\n" << std::endl;

		const auto& states1 = crypter.generate_output();
		for ( const auto& block : states1 )
			printblock(block->ret_block());			

		crypter.set_aes_state();
		crypter.cbc_decrypt();	

		crypter.unset_aes_state();	

		std::cout << std::endl << "Data after decryption [" << (unsigned int)aes_blocks << " blocks]\n" << std::endl;

		const auto& states2 = crypter.generate_output();
		for ( const auto& block : states2 )
			printblock(block->ret_block());			

		std::cout << std::endl << "Bytestream of all data \n" << std::endl;

		//bytestream of all data
		const auto& bytestream = crypter.ret_bytes();
		for ( const auto&b : bytestream ) {
			std::cout << (unsigned int)b << " ";
		}
		std::cout << std::endl;
	} catch (const error_handler& eh) {
		eh.call_err_msg();
	}		
}
