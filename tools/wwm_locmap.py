# Upstream tool vendored for local Arabic patch generation.
# Original project: https://github.com/oratakashi/where-winds-meet-indonesian-patch
# Review upstream license before redistributing modified copies.

#!/usr/bin/env python3
"""
wwm_locmap.py — reader/writer untuk file `translate_words_map_*`
(Where Winds Meet / NetEase Messiah Engine).

    pip install zstandard

    python wwm_locmap.py info   translate_words_map_en
    python wwm_locmap.py dump   translate_words_map_en strings.jsonl
    python wwm_locmap.py patch  translate_words_map_en strings.jsonl out_map_en

FORMAT (hasil reverse-engineering, terverifikasi round-trip 963.050 entri)
-------------------------------------------------------------------------
Container
  u32 magic        = 0xDEADBEEF
  u32 version      = 1
  u32 blockCount
  u32 reserved     = 0
  u32[blockCount] endOffset      # relatif terhadap akhir tabel ini

Block
  u8  codec        = 4  (zstd)
  u32 compressedSize
  u32 uncompressedSize
  u8[compressedSize] payload

Block 0  = index  : u64 totalEntries, u64 dataBlockCount, u32[dataBlockCount] id
Block 1..n = shard: hash map gaya SwissTable (absl::flat_hash_map)
  u64 capacity, u64 size, u64 seed
  u8[capacity] ctrl      (0x80 kosong / 0xFE deleted -> >=0x80 dilewati,
                          <0x80 = terisi / H2)
  u8 0xFF sentinel + u8[15] cloned ctrl + padding ke kelipatan 8
  slot[capacity] { u64 keyHash; u32 relOffset; u32 byteLen; }   # 16 byte
  <string blob>

  nilai = blok[ alamat_field_relOffset + relOffset : + byteLen ]
          ^ relative pointer, BUKAN offset absolut

  shardIndex = (keyHash % dataBlockCount) + 1

CATATAN PENTING
  Kunci (teks sumber bahasa Inggris) TIDAK disimpan — hanya hash 64-bit-nya.
  Jadi map ini satu arah: hash(teks_inggris) -> teks_terjemahan.
  Karena itu patch bahasa apa pun WAJIB dimainkan dengan Game Language = English:
  runtime menghitung hash dari string Inggris, lalu menukarnya dengan nilai di sini.

  Konsekuensinya untuk modding: kita TIDAK perlu (dan tidak bisa) membangun ulang
  tabel hash. Cukup pertahankan ctrl + keyHash + posisi slot apa adanya, lalu
  tulis ulang string blob dan perbarui relOffset/byteLen tiap slot.
"""
import argparse, json, os, struct, sys

try:
    import zstandard as zstd
except ImportError:
    sys.exit("butuh: pip install zstandard")

MAGIC = 0xDEADBEEF
CODEC_ZSTD = 4
CODEC_ZSTD_DICT = 5          # container v2: zstd frame compressed with the file's dictionary

# Container v2 (WWM China, see Format-Spec.md §8):
#   u32 magic | u32 version=2 | u32 mode
#   mode 6 only: u32 dictSize | u8[dictSize] zstd dictionary XOR keystream
#   u64 blockCount | u32[blockCount] endOffset | blocks (codec 4 or 5)
# Every mode-6 file in the client shares one keystream; it is recovered with
# cn/tools/find_dict_in_dump.py. The encrypted dictionary is written back
# verbatim, so patching never needs to re-encrypt anything.
MODE_ZSTD, MODE_ZSTD_DICT = 4, 6
KEYSTREAM_PATH = os.environ.get('WWM_KEYSTREAM') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'cn', 'work', 'keystream_v2.bin')

# `translate_words_map_*_diff` (incremental patch shipped between game updates)
# uses this exact same container/shard format, but only carries entries that
# changed since the base map. A key removed since the base version is marked
# with this single-byte sentinel instead of being absent from the shard.
TOMBSTONE = b'\xff'


# ---------------------------------------------------------------- container
def load_keystream(path=None):
    path = path or KEYSTREAM_PATH
    if not os.path.exists(path):
        raise ValueError(
            "container v2 butuh keystream kamus (%s tidak ada) — buat dengan "
            "cn/tools/find_dict_in_dump.py atau set WWM_KEYSTREAM" % path)
    with open(path, 'rb') as f:
        return f.read()


def _xor(a, b):
    return (int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')).to_bytes(len(a), 'little')


def _zdict(raw):
    return zstd.ZstdCompressionDict(raw, dict_type=zstd.DICT_TYPE_FULLDICT)


def read_container_ex(path, keystream=None):
    """Read a v1 or v2 container. Returns (hdr, blocks); hdr is a dict with
    `version`, `mode` and, for mode 6, `enc_dict` (as stored) and `zdict`
    (decrypted). Pass hdr unchanged to write_container_ex()."""
    with open(path, 'rb') as f:
        d = f.read()
    magic, ver = struct.unpack_from('<II', d, 0)
    if magic != MAGIC:
        raise ValueError("magic tidak cocok: %08x" % magic)
    hdr = {"version": ver, "mode": MODE_ZSTD, "enc_dict": None, "zdict": None}
    if ver == 1:
        cnt, = struct.unpack_from('<I', d, 8)
        p = 16
    elif ver == 2:
        hdr["mode"], = struct.unpack_from('<I', d, 8)
        p = 12
        if hdr["mode"] == MODE_ZSTD_DICT:
            ds, = struct.unpack_from('<I', d, 12)
            enc = d[16:16 + ds]
            ks = keystream if keystream is not None else load_keystream()
            if len(ks) < ds:
                raise ValueError("keystream %d byte < kamus %d byte" % (len(ks), ds))
            hdr["enc_dict"], hdr["zdict"] = enc, _xor(enc, ks[:ds])
            if hdr["zdict"][:4] != b'\x37\xa4\x30\xec':
                raise ValueError("kamus hasil dekripsi tidak valid (keystream salah?)")
            p = 16 + ds
        elif hdr["mode"] != MODE_ZSTD:
            raise ValueError("mode container v2 tak dikenal: %d" % hdr["mode"])
        cnt, = struct.unpack_from('<Q', d, p)
        p += 8
    else:
        raise ValueError("versi container tak dikenal: %d" % ver)
    if cnt == 0:
        raise ValueError("container tanpa blok (blockCount = 0)")
    offs = struct.unpack_from('<%dI' % cnt, d, p)
    base = p + cnt * 4
    if base + offs[-1] != len(d):
        raise ValueError("ukuran file tidak konsisten dengan tabel offset")
    dctx = {CODEC_ZSTD: zstd.ZstdDecompressor()}
    if hdr["zdict"]:
        dctx[CODEC_ZSTD_DICT] = zstd.ZstdDecompressor(dict_data=_zdict(hdr["zdict"]))
    blocks = []
    for i in range(cnt):
        s = base + (offs[i - 1] if i else 0)
        b = d[s:base + offs[i]]
        codec, cs, us = struct.unpack_from('<BII', b, 0)
        if codec not in dctx:
            raise ValueError("codec tak dikenal: %d" % codec)
        raw = dctx[codec].decompress(b[9:9 + cs], max_output_size=us)
        if len(raw) != us:
            raise ValueError("blok %d: ukuran hasil dekompresi %d != %d"
                             % (i, len(raw), us))
        blocks.append(raw)
    return hdr, blocks


def write_container_ex(path, hdr, blocks, level=19, threads=-1):
    if hdr["zdict"]:
        codec = CODEC_ZSTD_DICT
        cctx = zstd.ZstdCompressor(level=level, threads=threads,
                                   dict_data=_zdict(hdr["zdict"]), write_dict_id=True,
                                   write_content_size=True, write_checksum=False)
    else:
        codec = CODEC_ZSTD
        cctx = zstd.ZstdCompressor(level=level, threads=threads)
    payloads = [struct.pack('<BII', codec, len(c), len(r)) + c
                for r, c in ((r, cctx.compress(r)) for r in blocks)]
    if hdr["version"] == 1:
        out = bytearray(struct.pack('<IIII', MAGIC, 1, len(blocks), 0))
    else:
        out = bytearray(struct.pack('<III', MAGIC, 2, hdr["mode"]))
        if hdr["mode"] == MODE_ZSTD_DICT:
            out += struct.pack('<I', len(hdr["enc_dict"])) + hdr["enc_dict"]
        out += struct.pack('<Q', len(blocks))
    acc, table = 0, []
    for p in payloads:
        acc += len(p)
        table.append(acc)
    out += struct.pack('<%dI' % len(table), *table)
    for p in payloads:
        out += p
    with open(path, 'wb') as f:
        f.write(out)


def read_container(path):
    """v1-style API: (version, blocks). Use read_container_ex to also keep the
    v2 header needed to write the file back."""
    hdr, blocks = read_container_ex(path)
    return hdr["version"], blocks


def write_container(path, ver, blocks, level=19, threads=-1):
    """v1-only writer kept for existing callers; v2 needs write_container_ex."""
    if ver != 1:
        raise ValueError("write_container hanya untuk v1; pakai write_container_ex")
    write_container_ex(path, {"version": 1, "mode": MODE_ZSTD, "enc_dict": None,
                              "zdict": None}, blocks, level, threads)


# -------------------------------------------------------------------- shard
def _slots_off(cap):
    o = 24 + cap + 1 + 15
    return o + (-o) % 8


def parse_index(blk):
    total, nblocks = struct.unpack_from('<QQ', blk, 0)
    return total, nblocks


def parse_shard(blk):
    cap, size, seed = struct.unpack_from('<QQQ', blk, 0)
    ctrl = blk[24:24 + cap]
    if blk[24 + cap] != 0xFF:
        raise ValueError("sentinel hilang — layout tidak cocok")
    S = _slots_off(cap)
    out = []
    for i, c in enumerate(ctrl):
        if c >= 0x80:
            continue
        p = S + i * 16
        h, rel, ln = struct.unpack_from('<QII', blk, p)
        a = p + 8 + rel
        out.append((i, h, blk[a:a + ln]))
    if len(out) != size:
        raise ValueError("jumlah slot terisi != size")
    return cap, seed, out


def rebuild_shard(orig, values):
    """values: dict slotIndex -> bytes. ctrl/keyHash/posisi slot dipertahankan."""
    cap, size, seed = struct.unpack_from('<QQQ', orig, 0)
    S = _slots_off(cap)
    head = bytearray(orig[:S + cap * 16])
    ctrl = orig[24:24 + cap]
    blob, pool = bytearray(), {}
    for i, c in enumerate(ctrl):
        if c >= 0x80:
            continue
        v = values[i]
        if v not in pool:                       # dedup string identik
            pool[v] = len(blob)
            blob += v
        field = S + i * 16 + 8                  # alamat field relOffset
        struct.pack_into('<II', head, field,
                         len(head) + pool[v] - field, len(v))
    return bytes(head) + bytes(blob)


# --------------------------------------------------------------------- CLI
def cmd_info(a):
    ver, blocks = read_container(a.src)
    total, nblocks = parse_index(blocks[0])
    print("version        :", ver)
    print("blocks         : %d (1 index + %d shard)" % (len(blocks), nblocks))
    print("entries (index):", total)
    n, deleted = 0, 0
    for b in blocks[1:]:
        _, _, ents = parse_shard(b)
        n += len(ents)
        deleted += sum(1 for _, _, v in ents if v == TOMBSTONE)
    print("entries parsed :", n)
    if deleted:
        print("  deleted (tombstone 0xFF):", deleted)
    if n != total:
        print("note: parsed count != index total -- file terlihat seperti "
              "*_diff (hanya berisi key yang berubah/terhapus sejak versi dasar)")


def cmd_dump(a):
    ver, blocks = read_container(a.src)
    deleted = 0
    with open(a.out, 'w', encoding='utf-8') as f:
        for bi, blk in enumerate(blocks[1:], 1):
            _, _, ents = parse_shard(blk)
            for slot, h, v in ents:
                rec = {"b": bi, "s": slot, "h": "%016x" % h}
                if v == TOMBSTONE:
                    rec["deleted"] = True
                    deleted += 1
                else:
                    try:
                        rec["v"] = v.decode('utf-8')
                    except UnicodeDecodeError as e:
                        raise ValueError(
                            "nilai biner tak terduga di blok %d slot %d "
                            "(bukan UTF-8, bukan tombstone 0xFF): %r"
                            % (bi, slot, v[:32])) from e
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("ditulis:", a.out)
    if deleted:
        print("entri terhapus (tombstone):", deleted)


def cmd_patch(a):
    hdr, blocks = read_container_ex(a.src)
    edits = {}
    with open(a.jsonl, encoding='utf-8') as f:
        for ln, line in enumerate(f, 1):
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("deleted"):
                v = TOMBSTONE
            elif "v" in r:
                v = r["v"].encode('utf-8', 'surrogateescape')
            else:
                raise ValueError("%s baris %d: tidak ada field 'v' maupun "
                                 "'deleted'" % (a.jsonl, ln))
            edits.setdefault(r["b"], {})[r["s"]] = (r.get("h"), v, ln)
    bad = sorted(b for b in edits if not 1 <= b < len(blocks))
    if bad:
        raise ValueError("%s: block di luar jangkauan 1..%d: %s"
                         % (a.jsonl, len(blocks) - 1, bad[:10]))
    out = [blocks[0]]
    for bi, blk in enumerate(blocks[1:], 1):
        _, _, ents = parse_shard(blk)
        vals = {s: v for s, _, v in ents}
        hashes = {s: h for s, h, _ in ents}
        for s, (h, v, ln) in edits.get(bi, {}).items():
            # b/s saja tidak cukup: JSONL dari dump versi game lain menunjuk
            # slot yang sama tapi key berbeda -> teks masuk ke tempat yang salah.
            if s not in hashes:
                raise ValueError("%s baris %d: blok %d slot %d bukan slot terisi"
                                 % (a.jsonl, ln, bi, s))
            if h is not None and int(h, 16) != hashes[s]:
                raise ValueError(
                    "%s baris %d: keyHash %s != %016x di blok %d slot %d "
                    "(JSONL di-dump dari versi file yang berbeda?)"
                    % (a.jsonl, ln, h, hashes[s], bi, s))
            vals[s] = v
        out.append(rebuild_shard(blk, vals))
    write_container_ex(a.out, hdr, out, level=a.level)
    print("ditulis:", a.out)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    i = sub.add_parser('info');  i.add_argument('src');  i.set_defaults(f=cmd_info)
    d = sub.add_parser('dump');  d.add_argument('src');  d.add_argument('out')
    d.set_defaults(f=cmd_dump)
    q = sub.add_parser('patch'); q.add_argument('src');  q.add_argument('jsonl')
    q.add_argument('out'); q.add_argument('--level', type=int, default=19)
    q.set_defaults(f=cmd_patch)
    a = p.parse_args()
    a.f(a)
