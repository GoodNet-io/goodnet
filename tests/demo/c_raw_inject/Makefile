# SPDX-License-Identifier: Apache-2.0
#
# Standalone Makefile for the raw_inject C demo client.
# Plain POSIX C — no goodnet SDK headers, no link-time goodnet bits.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11

raw_client: raw_client.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f raw_client

.PHONY: clean
