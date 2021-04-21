# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
# Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net>

TARGETS=
ifndef USE_LIBSODIUM
TARGETS += blake3
endif

libs: $(TARGETS)

.PHONY: blake3 clean realclean

blake3:
	$(MAKE) -C blake3/c

clean realclean:
	$(MAKE) -C blake3/c $@
