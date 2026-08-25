#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#define main cryptic_main

/* One reference and one sample are held at a time; the collection is streamed. */
typedef struct {
	unsigned char  *p;
	size_t		n;
} Buf;
static void	die(const char *s){
	fprintf(stderr, "cryptic: %s\n", s);
	exit(1);
}
static Buf readseq(const char *fn){
	FILE	       *f = fopen(fn, "rb");
	if (!f)
		die("cannot open input");
	if (fseek(f, 0, SEEK_END) || ftell(f) < 0)
		die("cannot size input");
	long		z = ftell(f);
	rewind(f);
	Buf		b = {(unsigned char *)malloc((size_t) z + 1), (size_t) z};
	if (!b.p || fread(b.p, 1, b.n, f) != b.n)
		die("cannot read input");
	fclose(f);
	if (b.n && b.p[b.n - 1] == '\n')
		b.n--;
	if (b.n && b.p[b.n - 1] == '\r')
		die("CR is not permitted");
	return b;
}
static void	put8(FILE * f, uint64_t x) {
	for (int i = 0; i < 8; i++) {
		fputc((int)x & 255, f);
		x >>= 8;
	}
}
static uint64_t get8(FILE * f) {
	uint64_t	x = 0;
	for (int i = 0; i < 8; i++) {
		int		c = fgetc(f);
		if (c < 0)
			die("truncated archive");
		x |= (uint64_t) c << (8 * i);
	} return x;
}
static void	putv(FILE * f, uint64_t x) {
	while (x >= 128) {
		fputc((int)(x | 128), f);
		x >>= 7;
	} fputc((int)x, f);
}
static uint64_t getv(FILE * f) {
	uint64_t	x = 0;
	int		s = 0;
	for (int i = 0; i < 10; i++) {
		int		c = fgetc(f);
		if (c < 0 || (i == 9 && c > 1))
			die("invalid varint");
		x |= (uint64_t) (c & 127) << s;
		if (!(c & 128))
			return x;
		s += 7;
	} die("invalid varint");
	return 0;
}
static int
base(unsigned char c)
{
	return c == 'A' || c == 'C' || c == 'G' || c == 'T' || c == 'N';
}
/* Dependency-free SHA-256 supports archive integrity on ordinary C toolchains. */
static uint32_t rr(uint32_t x, int n){
	return (x >> n) | (x << (32 - n));
}
static void	hash(const unsigned char *p, size_t n, unsigned char h[32]){
	static const	uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	uint32_t	a, b, c, d, e, f, g, q, w[64], H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	uint64_t	bits = (uint64_t) n * 8;
	size_t		z = ((n + 9 + 63) / 64) * 64;
	unsigned char  *x = calloc(1, z);
	if (!x)
		die("out of memory");
	memcpy(x, p, n);
	x[n] = 128;
	for (int i = 0; i < 8; i++)
		x[z - 1 - i] = (unsigned char)(bits >> (8 * i));
	for (size_t off = 0; off < z; off += 64) {
		for (int i = 0; i < 16; i++)
			w[i] = (uint32_t) x[off + 4 * i] << 24 | (uint32_t) x[off + 4 * i + 1] << 16 | (uint32_t) x[off + 4 * i + 2] << 8 | x[off + 4 * i + 3];
		for (int i = 16; i < 64; i++) {
			uint32_t	s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3),
					s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		} a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		q = H[7];
		for (int i = 0; i < 64; i++) {
			uint32_t	S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25),
					ch = (e & f) ^ ((~e) & g), t1 = q + S1 + ch + K[i] + w[i],
					S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22),
					maj = (a & b) ^ (a & c) ^ (b & c),
					t2 = S0 + maj;
			q = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		} H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += q;
	} free(x);
	for (int i = 0; i < 8; i++) {
		h[4 * i] = H[i] >> 24;
		h[4 * i + 1] = H[i] >> 16;
		h[4 * i + 2] = H[i] >> 8;
		h[4 * i + 3] = H[i];
	}
}
static int	cmpstr(const void *a, const void *b){
	return strcmp(*(const char **)a, *(const char **)b);
}
static char **	names(const char *d, size_t * n){
	DIR	       *x = opendir(d);
	if (!x)
		die("cannot open input directory");
	char	      **v = NULL;
	struct dirent  *e;
	while ((e = readdir(x))) {
		size_t		l = strlen(e->d_name);
		if (l < 4 || strcmp(e->d_name + l - 4, ".seq"))
			continue;
		v = realloc(v, (*n + 1) * sizeof(*v));
		if (!v)
			die("out of memory");
		v[(*n)++] = strdup(e->d_name);
	} closedir(x);
	qsort(v, *n, sizeof(*v), cmpstr);
	return v;
}
static void	checkseq(Buf b, size_t len) {
	if (b.n != len)
		die("sequence length mismatch");
	for (size_t i = 0; i < b.n; i++)
		if (!base(b.p[i]))
			die("invalid DNA character");
}
/* Sorted filenames and delta records make output reproducible across filesystems. */
static void	encode(const char *ref, const char *dir, const char *out){
	Buf		r = readseq(ref);
	unsigned char	rh[32];
	hash(r.p, r.n, rh);
	size_t		n = 0;
	char	      **v = names(dir, &n);
	FILE	       *f = fopen(out, "wb");
	if (!f)
		die("cannot create archive");
	fwrite("CRYPTIC\1", 1, 8, f);
	put8(f, 1);
	put8(f, r.n);
	fwrite(rh, 1, 32, f);
	put8(f, n);
	for (size_t k = 0; k < n; k++) {
		char		path[4096];
		snprintf(path, sizeof path, "%s/%s", dir, v[k]);
		Buf		s = readseq(path);
		checkseq(s, r.n);
		unsigned char	sh[32];
		hash(s.p, s.n, sh);
		uint64_t	records = 0;
		for (size_t i = 0; i < s.n;) {
			if (s.p[i] == r.p[i]) {
				i++;
				continue;
			} if (s.p[i] == 'N') {
				size_t		j = i + 1;
				while (j < s.n && s.p[j] == 'N' && s.p[j] != r.p[j])
					j++;
				records++;
				i = j;
			} else {
				records++;
				i++;
			}
		} putv(f, strlen(v[k]));
		fwrite(v[k], 1, strlen(v[k]), f);
		put8(f, records);
		fwrite(sh, 1, 32, f);
		size_t		prev = 0;
		for (size_t i = 0; i < s.n;) {
			if (s.p[i] == r.p[i]) {
				i++;
				continue;
			} if (s.p[i] == 'N') {
				size_t		j = i + 1;
				while (j < s.n && s.p[j] == 'N' && s.p[j] != r.p[j])
					j++;
				fputc(1, f);
				putv(f, i - prev);
				putv(f, j - i);
				prev = j;
				i = j;
			} else {
				fputc(0, f);
				putv(f, i - prev);
				fputc(s.p[i], f);
				prev = i + 1;
				i++;
			}
		} free(s.p);
	} fclose(f);
	free(r.p);
	for (size_t i = 0; i < n; i++)
		free(v[i]);
	free(v);
}
static void	openarc(FILE * f, const char *ref){
	char		m[8];
	if (fread(m, 1, 8, f) != 8 || memcmp(m, "CRYPTIC\1", 8))
		die("bad archive magic");
	if (get8(f) != 1)
		die("unsupported archive version");
	uint64_t	l = get8(f);
	Buf		r = readseq(ref);
	unsigned char	h[32], x[32];
	hash(r.p, r.n, h);
	if (l != r.n || fread(x, 1, 32, f) != 32 || memcmp(h, x, 32))
		die("reference does not match archive");
	free(r.p);
}
static void	decode(const char *ref, const char *in, const char *out, int verify){
	FILE	       *f = fopen(in, "rb");
	if (!f)
		die("cannot open archive");
	openarc(f, ref);
	uint64_t	n = get8(f);
	Buf		r = readseq(ref);
	for (uint64_t k = 0; k < n; k++) {
		uint64_t	nl = getv(f);
		if (nl == 0 || nl > 4096)
			die("invalid filename length");
		char		name[4097];
		if (fread(name, 1, nl, f) != nl)
			die("truncated filename");
		name[nl] = 0;
		for (uint64_t i = 0; i < nl; i++)
			if (name[i] == '/' || name[i] == '\\' || name[i] == '.' && (i == 0 || name[i - 1] == '/'))
				die("unsafe filename");
		uint64_t	nr = get8(f);
		unsigned char	want[32];
		if (fread(want, 1, 32, f) != 32)
			die("truncated sample hash");
		unsigned char  *s = malloc(r.n);
		if (!s)
			die("out of memory");
		memcpy(s, r.p, r.n);
		uint64_t	pos = 0;
		for (uint64_t j = 0; j < nr; j++) {
			int		t = fgetc(f);
			uint64_t	d = getv(f);
			if (d > r.n - pos)
				die("invalid position delta");
			pos += d;
			if (t == 0) {
				int		c = fgetc(f);
				if (c < 0 || !base((unsigned char)c) || pos >= r.n)
					die("invalid substitution");
				s[pos++] = (unsigned char)c;
			} else if (t == 1) {
				uint64_t	z = getv(f);
				if (z == 0 || z > r.n - pos)
					die("invalid N run");
				for (uint64_t q = 0; q < z; q++)
					s[pos + q] = 'N';
				pos += z;
			} else
				die("invalid record type");
		} unsigned char	got[32];
		hash(s, r.n, got);
		if (memcmp(want, got, 32))
			die("sample integrity failure");
		if (!verify) {
			mkdir(out, 0777);
			char		path[4096];
			snprintf(path, sizeof path, "%s/%s", out, name);
			FILE	       *o = fopen(path, "wb");
			if (!o)
				die("cannot create output");
			fwrite(s, 1, r.n, o);
			fputc('\n', o);
			fclose(o);
		} free(s);
	} free(r.p);
	fclose(f);
}
static void	stats(const char *ref, const char *dir){
	Buf		r = readseq(ref);
	size_t		n = 0;
	char	      **v = names(dir, &n);
	uint64_t	total = 0, min = UINT64_MAX, max = 0;
	for (size_t k = 0; k < n; k++) {
		char		p[4096];
		snprintf(p, sizeof p, "%s/%s", dir, v[k]);
		Buf		s = readseq(p);
		checkseq(s, r.n);
		uint64_t	d = 0;
		for (size_t i = 0; i < r.n; i++)
			d += s.p[i] != r.p[i];
		total += d;
		if (d < min)
			min = d;
		if (d > max)
			max = d;
		free(s.p);
	} printf("reference length: %zu\nsamples: %zu\ntotal differences: %llu\ndifferences/sample: min %llu mean %.2f max %llu\nidentical: %.5f%%\n", r.n, n, (unsigned long long)total, (unsigned long long)min, n ? (double)total / n : 0, (unsigned long long)max, 100.0 * (1.0 - (double)total / (n * r.n)));
}
static void	mkparents(const char *p){
	char		b[4096];
	size_t		n = strlen(p);
	if (n >= sizeof b)
		die("path too long");
	memcpy(b, p, n + 1);
	for (size_t i = 1; i < n; i++)
		if (b[i] == '/') {
			b[i] = 0;
			mkdir(b, 0777);
			b[i] = '/';
		}
}
/* FASTA wrapping and CRLF endings are normalized into canonical .seq lines. */
static void	convert_fasta(const char *in, const char *out){
	FILE	       *f = fopen(in, "rb");
	if (!f)
		die("cannot open FASTA");
	char		line[65536], path[4096];
	snprintf(path, sizeof path, "%s", out);
	mkparents(path);
	FILE	       *o = fopen(path, "wb");
	if (!o)
		die("cannot create seq output");
	int		seen = 0;
	while (fgets(line, sizeof line, f)) {
		size_t		n = strlen(line);
		while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = 0;
		if (line[0] == '>') {
			if (seen)
				fputc('\n', o);
			seen = 1;
			continue;
		} if (!seen)
			die("FASTA sequence precedes header");
		for (size_t i = 0; i < n; i++) {
			if (line[i] == ' ' || line[i] == '\t')
				continue;
			if (!base((unsigned char)line[i]))
				die("invalid FASTA DNA character");
			fputc(line[i], o);
		}
	} if (seen)
		fputc('\n', o);
	fclose(o);
	fclose(f);
}
static void	fasta_walk(const char *root, const char *rel, const char *out){
	char		dir[4096];
	snprintf(dir, sizeof dir, "%s/%s", root, rel);
	DIR	       *d = opendir(dir);
	if (!d)
		die("cannot open FASTA directory");
	struct dirent  *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		char		r[4096], in[4096], dest[4096];
		snprintf(r, sizeof r, "%s%s%s", rel, *rel ? "/" : "", e->d_name);
		snprintf(in, sizeof in, "%s/%s", root, r);
		struct stat	st;
		if (stat(in, &st))
			die("cannot stat FASTA path");
		if (S_ISDIR(st.st_mode)) {
			fasta_walk(root, r, out);
			continue;
		} size_t	n = strlen(e->d_name);
		if (n < 3)
			continue;
		const char     *ext = e->d_name + n - 3;
		if (strcmp(ext, ".fa") && strcmp(ext, ".fna") && strcmp(ext, "sta"))
			continue;
		snprintf(dest, sizeof dest, "%s/%s", out, r);
		char	       *dot = strrchr(dest, '.');
		if (dot)
			memcpy(dot, ".seq", 5);
		convert_fasta(in, dest);
	} closedir(d);
}

/* FNV-1a gives a stable bucket for a filename stem on every platform. */
static uint64_t stem_bucket(const char *name, size_t files_per_shard){
	char stem[4096];
	const char *dot = strrchr(name, '.');
	size_t n = dot ? (size_t)(dot - name) : strlen(name);
	if (n == 0 || n >= sizeof(stem)) die("invalid filename stem");
	memcpy(stem, name, n);
	stem[n] = 0;
	uint64_t h = UINT64_C(1469598103934665603);
	for (size_t i = 0; i < n; ++i) {
		h ^= (unsigned char)stem[i];
		h *= UINT64_C(1099511628211);
	}
	return h % files_per_shard;
}

static void copy_file(const char *in, const char *out){
	FILE *a = fopen(in, "rb"), *b;
	unsigned char buf[65536];
	if (!a) die("cannot open shard input");
	mkparents(out);
	b = fopen(out, "wb");
	if (!b) die("cannot create shard output");
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), a)) != 0)
		if (fwrite(buf, 1, n, b) != n) die("cannot write shard output");
	if (ferror(a)) die("cannot read shard input");
	fclose(a);
	fclose(b);
}

static void shard_walk(const char *root, const char *rel, const char *out,
			       const char *extension, size_t files_per_shard){
	char dir[4096];
	DIR *d;
	struct dirent *e;
	snprintf(dir, sizeof(dir), "%s/%s", root, rel);
	d = opendir(dir);
	if (!d) die("cannot open shard input directory");
	while ((e = readdir(d)) != NULL) {
		char r[4096], in[4096], dest[4096], shard[64];
		struct stat st;
		size_t n = strlen(e->d_name), el = strlen(extension);
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
		snprintf(r, sizeof(r), "%s%s%s", rel, *rel ? "/" : "", e->d_name);
		snprintf(in, sizeof(in), "%s/%s", root, r);
		if (stat(in, &st)) die("cannot stat shard input");
		if (S_ISDIR(st.st_mode)) {
			shard_walk(root, r, out, extension, files_per_shard);
			continue;
		}
		if (n < el || strcmp(e->d_name + n - el, extension)) continue;
		snprintf(shard, sizeof(shard), "%08llu",
			 (unsigned long long)stem_bucket(e->d_name, files_per_shard));
		snprintf(dest, sizeof(dest), "%s/%s/%s", out, shard, e->d_name);
		copy_file(in, dest);
	}
	closedir(d);
}

static int shard_command(int ac, char **av){
	const char *in = NULL, *out = NULL, *extension = NULL;
	size_t files_per_shard = 1000;
	for (int i = 2; i < ac; ++i) {
		if (!strcmp(av[i], "--input-dir") && i + 1 < ac) in = av[++i];
		else if (!strcmp(av[i], "--output-dir") && i + 1 < ac) out = av[++i];
		else if (!strcmp(av[i], "--extension") && i + 1 < ac) extension = av[++i];
		else if (!strcmp(av[i], "--files-per-shard") && i + 1 < ac)
			files_per_shard = (size_t)strtoull(av[++i], NULL, 10);
		else if (!strcmp(av[i], "--help")) {
			puts("cryptic shard --input-dir D --output-dir O --extension .fasta "
			     "[--files-per-shard 1000]");
			return 0;
		} else die("unknown shard option");
	}
	if (!in || !out || !extension || files_per_shard == 0)
		die("shard needs --input-dir --output-dir --extension and positive --files-per-shard");
	shard_walk(in, "", out, extension, files_per_shard);
	return 0;
}
#undef main
int		legacy_main(int, char **);
int		main(int ac, char **av){
	if (ac >= 2 && !strcmp(av[1], "shard"))
		return shard_command(ac, av);
	if (ac >= 2 && !strcmp(av[1], "fasta-to-seq")) {
		const char     *in = NULL, *out = NULL;
		for (int i = 2; i < ac; i++) {
			if (!strcmp(av[i], "--input-dir") && i + 1 < ac)
				in = av[++i];
			else if (!strcmp(av[i], "--output-dir") && i + 1 < ac)
				out = av[++i];
			else if (!strcmp(av[i], "--help")) {
				puts("cryptic fasta-to-seq --input-dir FASTAS --output-dir SEQS");
				return 0;
			} else
				die("unknown option");
		} if (!in || !out)
			die("fasta-to-seq needs --input-dir and --output-dir");
		fasta_walk(in, "", out);
		return 0;
	} return legacy_main(ac, av);
}
#define main legacy_main
int		main(int ac, char **av){
	if (ac < 2 || !strcmp(av[1], "--help") || !strcmp(av[1], "-h")) {
		puts("usage: cryptic <command> [options]\n\ncommands:\n  encode   encode a directory\n  decode   restore samples\n  verify   validate an archive\n  inspect  show archive header\n  stats    report reference differences\n  fasta-to-seq convert FASTA shards\n  shard    copy matching files into deterministic buckets\n\nUse cryptic <command> --help for examples.");
		return ac < 2 ? 2 : 0;
	} const char   *ref = NULL, *dir = NULL, *in = NULL, *out = NULL;
	for (int i = 2; i < ac; i++) {
		if (!strcmp(av[i], "--reference") && i + 1 < ac)
			ref = av[++i];
		else if (!strcmp(av[i], "--input-dir") && i + 1 < ac)
			dir = av[++i];
		else if (!strcmp(av[i], "--input") && i + 1 < ac)
			in = av[++i];
		else if (!strcmp(av[i], "--output") && i + 1 < ac)
			out = av[++i];
		else if (!strcmp(av[i], "--output-dir") && i + 1 < ac)
			out = av[++i];
		else if (!strcmp(av[i], "--help")) {
			puts("cryptic encode --reference R --input-dir D --output A\ncryptic decode --reference R --input A --output-dir D\ncryptic verify --reference R --input A\ncryptic stats --reference R --input-dir D");
			return 0;
		} else
			die("unknown option");
	} if (!strcmp(av[1], "encode")) {
		if (!ref || !dir || !out)
			die("encode needs --reference --input-dir --output");
		encode(ref, dir, out);
	} else if (!strcmp(av[1], "decode")) {
		if (!ref || !in || !out)
			die("decode needs --reference --input --output-dir");
		decode(ref, in, out, 0);
	} else if (!strcmp(av[1], "verify")) {
		if (!ref || !in)
			die("verify needs --reference --input");
		decode(ref, in, NULL, 1);
		puts("archive verified");
	} else if (!strcmp(av[1], "stats")) {
		if (!ref || !dir)
			die("stats needs --reference --input-dir");
		stats(ref, dir);
	} else if (!strcmp(av[1], "inspect")) {
		if (!in)
			die("inspect needs --input");
		FILE	       *f = fopen(in, "rb");
		if (!f)
			die("cannot open archive");
		char		m[8];
		if (fread(m, 1, 8, f) != 8)
			die("truncated archive");
		printf("magic: %.8s\nversion: %llu\n", m, (unsigned long long)get8(f));
		fclose(f);
	} else
		die("unknown command");
	return 0;
}
