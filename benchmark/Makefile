# Build the benign control binaries used by the benchmark.
#
# These are compiled locally rather than committed: a binary in the repository
# is a binary a reviewer has to trust, and the sources make the behaviour
# auditable in a way a checked-in ELF never is.

CC      ?= gcc
CFLAGS  ?= -O1 -w
OUT     := samples
SOURCES := $(wildcard src/*.c)
TARGETS := $(patsubst src/%.c,$(OUT)/%,$(SOURCES))

.PHONY: all clean

all: $(TARGETS)
	@echo
	@echo "Built $(words $(TARGETS)) control binaries in $(OUT)/"

$(OUT)/%: src/%.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $<

$(OUT):
	mkdir -p $(OUT)

clean:
	rm -rf $(OUT)
