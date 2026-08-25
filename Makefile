CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?=

cryptic: src/main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: cryptic
	./cryptic stats --reference reference/NC_000962.3.seq --input-dir seqs >/dev/null
	./cryptic encode --reference reference/NC_000962.3.seq --input-dir seqs --output /tmp/cryptic-test.bin
	rm -rf /tmp/cryptic-restored && ./cryptic decode --reference reference/NC_000962.3.seq --input /tmp/cryptic-test.bin --output-dir /tmp/cryptic-restored
	./cryptic verify --reference reference/NC_000962.3.seq --input /tmp/cryptic-test.bin
	cmp seqs/SRR2024879.final.seq /tmp/cryptic-restored/SRR2024879.final.seq

clean:
	rm -f cryptic
.PHONY: test clean
