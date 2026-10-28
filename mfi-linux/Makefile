# libmfi — MFi accessory authentication for Linux vehicle hosts
#
#   make            build libmfi.a, libmfi.so and the mfid tool
#   make test       build and run the test suite (needs build/test-pki)
#   make selftest   run the CLI end to end against the test identity
#   make install    install into $(PREFIX) (default /usr/local)
#
# OpenSSL is discovered through pkg-config, then through common prefixes.

CC      ?= cc
AR      ?= ar
PREFIX  ?= /usr/local
CFLAGS  ?= -O2 -g
WARN    := -Wall -Wextra -Wno-unused-parameter
STD     := -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
ifeq ($(shell uname -s),Darwin)
STD     += -D_DARWIN_C_SOURCE
endif

PKG_OPENSSL_PREFIX := $(shell pkg-config --variable=prefix openssl 2>/dev/null)
OPENSSL_PREFIX ?= $(if $(PKG_OPENSSL_PREFIX),$(PKG_OPENSSL_PREFIX),$(firstword \
    $(wildcard /usr/local/opt/openssl@3 /opt/homebrew/opt/openssl@3 /opt/homebrew/opt/openssl \
               /usr/lib/x86_64-linux-gnu /usr)))

INCLUDES := -Iinclude
LIBS     :=
ifneq ($(OPENSSL_PREFIX),)
INCLUDES += -I$(OPENSSL_PREFIX)/include
LIBS     += -L$(OPENSSL_PREFIX)/lib
endif
LIBS += -lcrypto

ifeq ($(shell uname -s),Darwin)
LIBS += -Wl,-rpath,$(OPENSSL_PREFIX)/lib
endif

LIB_SRC := src/util.c src/crypto.c src/csm.c src/identity.c src/auth_local.c src/sap.c \
           src/iap2.c src/cp.c src/cp_sim.c src/i2c_linux.c src/link.c src/mfid_server.c
LIB_OBJ = $(patsubst src/%.c,$(BUILD)/obj/%.o,$(LIB_SRC))

BUILD := build

all: $(BUILD)/libmfi.a $(BUILD)/libmfi.so $(BUILD)/mfid

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/obj/%.o: src/%.c include/mfi/mfi.h src/mfi_internal.h | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

$(BUILD)/libmfi.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/libmfi.so: $(LIB_OBJ)
	$(CC) -shared -o $@ $^ $(LIBS)

$(BUILD)/mfid: cli/mfid.c $(BUILD)/libmfi.a
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDES) cli/mfid.c $(BUILD)/libmfi.a -o $@ $(LIBS) -lpthread

$(BUILD)/test_mfi: test/test_main.c $(BUILD)/libmfi.a
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDES) test/test_main.c $(BUILD)/libmfi.a -o $@ $(LIBS) -lpthread

test: $(BUILD)/test_mfi
	./$(BUILD)/test_mfi $(TEST_IDENTITY)

selftest: $(BUILD)/mfid $(BUILD)/test-identity
	./$(BUILD)/mfid --identity $(TEST_IDENTITY) selftest

clean:
	rm -rf $(BUILD)

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include/mfi
	install -m 0755 $(BUILD)/mfid $(DESTDIR)$(PREFIX)/bin/mfid
	install -m 0644 $(BUILD)/libmfi.a $(DESTDIR)$(PREFIX)/lib/libmfi.a
	install -m 0755 $(BUILD)/libmfi.so $(DESTDIR)$(PREFIX)/lib/libmfi.so
	install -m 0644 include/mfi/mfi.h $(DESTDIR)$(PREFIX)/include/mfi/mfi.h
	install -d $(DESTDIR)$(PREFIX)/share/mfi
	install -m 0644 README.md $(DESTDIR)$(PREFIX)/share/mfi/README.md

TEST_IDENTITY ?= $(BUILD)/test-identity

# A throwaway self-signed P-256 identity in the DiPlay directory layout, so the
# suite runs on a clean checkout with nothing but OpenSSL.
$(BUILD)/test-identity/identity.pk8:
	@mkdir -p $(BUILD)/test-identity
	openssl ecparam -name prime256v1 -genkey -noout -out $(BUILD)/test-identity/key.pem
	openssl pkcs8 -topk8 -nocrypt -in $(BUILD)/test-identity/key.pem -outform DER \
	    -out $(BUILD)/test-identity/identity.pk8
	openssl req -new -x509 -key $(BUILD)/test-identity/key.pem -days 3650 \
	    -subj "/O=MockMFI Test/CN=MockMFI Test Accessory" \
	    -out $(BUILD)/test-identity/leaf.pem
	openssl crl2pkcs7 -nocrl -certfile $(BUILD)/test-identity/leaf.pem -outform DER \
	    -out $(BUILD)/test-identity/certificate.p7b

$(BUILD)/test-identity: $(BUILD)/test-identity/identity.pk8

test: $(BUILD)/test_mfi $(BUILD)/test-identity

.PHONY: all test selftest clean install
