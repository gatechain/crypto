
SRCPATH     := $(shell pwd)

install:
	cd $(SRCPATH)/libsodium-fork && ./autogen.sh && ./configure --prefix=$(SRCPATH) && make install
