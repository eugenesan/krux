# cUR as a mainline-MicroPython user C module.
#
# The firmware tree is mainline MicroPython, not MaixPy.  Point the build
# here so it compiles the same cUR sources the host tests use, with the
# bundled SHA-256 backend instead of the K210 hardware one.
#
# USERMOD_DIR is the directory containing this file.  uUR.c and src are
# symlinks into the vendor/cUR submodule; keeping them inside this wrapper
# also keeps MicroPython from recursively including cUR's MaixPy makefile.

CUR_MOD_DIR := $(USERMOD_DIR)

SRC_USERMOD += $(CUR_MOD_DIR)/uUR.c
SRC_USERMOD += $(wildcard $(CUR_MOD_DIR)/src/*.c)
SRC_USERMOD += $(wildcard $(CUR_MOD_DIR)/src/types/*.c)
# cUR's MaixPy makefile relies on the K210 SHA peripheral and therefore does
# not list this file.  The Nexus build has no such peripheral, so use cUR's
# portable bundled SHA-256.
SRC_USERMOD += $(CUR_MOD_DIR)/src/sha256/sha256.c

CFLAGS_USERMOD += -I$(CUR_MOD_DIR) -I$(CUR_MOD_DIR)/src

# cUR deliberately keeps some fountain-coordinate arithmetic in double for
# interoperability, and its MicroPython print path promotes a float literal.
# The mainline unix port builds with -Werror; keep these as warnings rather
# than treating platform/compiler diagnostics as build failures.
CFLAGS_USERMOD += -Wno-error=double-promotion -Wno-error=float-conversion
