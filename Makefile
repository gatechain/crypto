
SRCPATH     := $(shell pwd)

install:
	cd $(SRCPATH)/libsodium-fork && ./autogen.sh && ./configure --prefix=$(SRCPATH) && make install
clean:
	cd $(SRCPATH)/libsodium-fork && \
		test ! -e Makefile || make clean
	#rm -rf $(SRCPATH)/lib
