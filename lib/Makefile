# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

OPENSWANSRCDIR?=$(shell cd ..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

srcdir?=$(shell pwd)/

SUBDIRS=libopenswan libalgoparse libpluto libcrypto libwhack libipsecconf liboswlog liboswkeys

ifeq ($(USE_IPSECPOLICY),true)
SUBDIRS+=libipsecpolicy
endif

ifeq ($(USE_BSDKAME),true)
SUBDIRS+=libbsdpfkey
endif

CARGO?=cargo
RUST_SUBDIRS=libxfrmeroute

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# programs

cleanall distclean mostlyclean realclean install programs checkprograms check clean spotless install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${srcdir}$$d/ OPENSWANSRCDIR=$(OPENSWANSRCDIR) $@ ) || exit 1;\
	done;
	for d in ${RUST_SUBDIRS} ; \
	@do \
		mkdir -p ${OBJDIRTOP}/lib/$$d; \
		echo Building $$d ;\
		(cd ${srcdir}/$$d && ${CARGO} build --target-dir ${OBJDIRTOP}/lib/$$d ); \
	done;


includes: ${OPENSWANSRCDIR}/include/openswan/xfrmroute.h

${OPENSWANSRCDIR}/include/openswan/xfrmroute.h: libxfrmeroute/Cargo.toml
	(cd libxfrmeroute && cbindgen ) > ${OPENSWANSRCDIR}/include/openswan/xfrmroute.h
