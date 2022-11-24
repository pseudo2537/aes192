CC = 				g++
CFLAGS = 			-std=c++17 -O3 -fno-unroll-loops -W -Wall

#target =			aes192
target =			crypter

#depcies =			datahandler/data_handler.cc fibo_lfsr/lfsr.cc
depcies =			aes192.cc datahandler/data_handler.cc fibo_lfsr/lfsr.cc

.PHONY: aes clean

aes: $(target).cc
	$(CC) $< -o $(target) $(depcies) $(CFLAGS)

clean:
	rm -f *.o
