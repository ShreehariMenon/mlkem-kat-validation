C=gcc
CFLAGS=-O2 -Wall

# You may need to adjust these paths if WolfSSL or AWS-LC are installed elsewhere
WOLFSSL_DIR ?= $(HOME)/wolfssl
AWSLC_DIR ?= $(HOME)/aws-lc

all: test_awslc_nist test_wolfssl_nist

test_wolfssl_nist: test_wolfssl_nist.c
	$(CC) $(CFLAGS) $< -o $@ \
	-I$(WOLFSSL_DIR) -I$(WOLFSSL_DIR)/wolfssl -I$(WOLFSSL_DIR)/build \
	-L$(WOLFSSL_DIR)/build -lwolfssl \
	-Wl,-rpath,$(WOLFSSL_DIR)/build

test_awslc_nist: test_awslc_nist.c
	$(CC) $(CFLAGS) $< -o $@ \
	-I$(AWSLC_DIR)/include \
	-L$(AWSLC_DIR)/build/crypto -lcrypto \
	-Wl,-rpath,$(AWSLC_DIR)/build/crypto


clean:
	rm -f test_wolfssl_nist test_awslc_nist test_pqclean_nist
