#
#  Copyright (C) 2011 Andreas Öman
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


WITH_LIBGIT2 := yes
WITH_CURL    := yes


BUILDDIR = ${CURDIR}/build

PROG=${BUILDDIR}/doozeragent

SRCS =  src/main.c \
	src/agent.c \
	src/job.c \
	src/git.c \
	src/doozerctrl.c \
	src/autobuild.c \
	src/makefile.c \
	src/artifact.c \
	src/spawn.c \
	src/heap_simple.c \

ifeq ($(shell uname),Linux)
SRCS +=	src/heap_btrfs.c \
	src/buildenv.c

LDFLAGS += -larchive

endif

LDFLAGS += -lz

install: ${PROG}
	install -D ${PROG} "${prefix}/bin/doozeragent"
uninstall:
	rm -f "${prefix}/bin/doozeragent"

include libsvc/libsvc.mk
-include $(DEPS)
