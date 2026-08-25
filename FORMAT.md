# CRYPTIC format

All integers are unsigned little-endian (the byte order is explicitly defined, so readers are portable); variable integers are unsigned LEB128. The header is `CRYPTIC\1`, `u64 version` (1), `u64 reference length`, 32-byte reference digest, and `u64 sample count`.

Each sample contains an LEB128 filename length and basename, `u64` record count, and a 32-byte sample digest. Records are type `0` (delta, replacement ASCII base) or type `1` (delta, run length, all `N`). Delta is from the position immediately after the previous record. Positions are zero-based. A final LF is canonical output but is not part of the sequence. The digest is SHA-256 in the implementation; readers must compare it after reconstruction and reject reference mismatches.
