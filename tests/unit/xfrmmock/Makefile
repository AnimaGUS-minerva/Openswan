# Makefile for the Openswan in-tree test cases
# Copyright (C) 2014 Michael Richardson <mcr@xelerance.com>
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

OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto

include ${OPENSWANSRCDIR}/Makefile.inc

UNITTESTS=
UNITTESTS+=xf12-parentR2
UNITTESTS+=xf13-parentI3

# disabled due to #7555
#UNITTESTS+=xf79-childQR1

# disabled due to #7554
#UNITTESTS+=xf88-v1certQI1
#UNITTESTS+=xf89-v1certQR1
#UNITTESTS+=xf90-v1certQI2

# disabled due to #7554
#UNITTESTS+=xf109-v1rwnatQR1

UNITTESTS+=xf113-vtiI3
UNITTESTS+=xf129-peerA-I5
UNITTESTS+=xf147-peerA-duplicate-state

programs pcapupdate clean check:
	@for unittest in ${UNITTESTS}; do ${MAKE} -C $$unittest $@; done

testlist:
	@echo ${UNITTESTS}

rununittests:
	./run-unit-tests.sh
