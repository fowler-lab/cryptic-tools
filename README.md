# cryptic

`cryptic` is a deterministic, lossless reference-difference archive for aligned five-symbol DNA `.seq` files.

Build with `make`; run `make test`. Example commands are shown by `./cryptic --help`. The reference and samples accept exactly `A C G T N` and one optional final LF. Filenames are sorted bytewise and stored as basenames. Decoding refuses a mismatched reference and validates every reconstructed sample.

The format is documented in [FORMAT.md](FORMAT.md). The raw archive has no zstd dependency; an external `zstd` layer may be applied to `.cryptic` files.

FASTA inputs can be normalized and sharded with:

    ./cryptic shard --input-dir fastas --output-dir sharded \
        --extension .fasta --number-of-shards 100 --preprocess-fasta

Normalized FASTA files use the input filename stem as the header, one sequence
line, and LF endings. `encode` accepts both `.seq` and FASTA files, ignoring
FASTA headers. `decode` writes canonical `.fasta` files with `>stem` headers.
