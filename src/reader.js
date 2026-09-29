/* Bounds-checked binary reader — every read validates the range and throws
   an ElfError carrying the byte offset, so truncated/corrupt files fail
   with a descriptive message instead of undefined behavior. */

export class ElfError extends Error {
  constructor(message, offset) {
    super(offset !== undefined ? `${message} (at byte ${offset})` : message);
    this.name = 'ElfError';
    this.offset = offset;
  }
}

export class ByteReader {
  constructor(bytes, endian = 'lsb') {
    if (!(bytes instanceof Uint8Array)) throw new ElfError('input must be a Uint8Array');
    this.bytes = bytes;
    this.lsb = endian === 'lsb';
    this.pos = 0;
  }

  get length() { return this.bytes.length; }

  seek(pos) {
    if (pos < 0 || pos > this.bytes.length) throw new ElfError('seek out of range', pos);
    this.pos = pos;
    return this;
  }

  need(n, what) {
    if (this.pos + n > this.bytes.length) {
      throw new ElfError(`truncated file: ${what} needs ${n} byte(s) past byte ${this.pos}`, this.pos);
    }
    const start = this.pos;
    this.pos += n;
    return start;
  }

  u8(what = 'u8') {
    const at = this.need(1, what);
    return this.bytes[at];
  }

  u16(what = 'u16') {
    const at = this.need(2, what);
    const b = this.bytes;
    return this.lsb ? b[at] | (b[at + 1] << 8) : (b[at] << 8) | b[at + 1];
  }

  u32(what = 'u32') {
    const at = this.need(4, what);
    const b = this.bytes;
    return this.lsb
      ? ((b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0)
      : (((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0);
  }

  u64(what = 'u64') {
    const at = this.need(8, what);
    let v = 0n;
    for (let i = 0; i < 8; i++) {
      const sh = BigInt((this.lsb ? i : 7 - i) * 8);
      v |= BigInt(this.bytes[at + i]) << sh;
    }
    return v;
  }

  i64(what = 's64') {
    const v = this.u64(what);
    return v >= 2n ** 63n ? v - 2n ** 64n : v;
  }

  /* NUL-terminated string from a strtab (absolute offset), bounds-checked. */
  cstrAt(offset, what = 'string') {
    if (offset >= this.bytes.length) throw new ElfError(`string offset ${offset} out of range`, offset);
    let end = offset;
    while (end < this.bytes.length && this.bytes[end] !== 0) end++;
    if (end >= this.bytes.length) throw new ElfError(`unterminated ${what}`, offset);
    return new TextDecoder('latin1').decode(this.bytes.subarray(offset, end));
  }

  bytesAt(offset, length, what = 'bytes') {
    if (offset < 0 || offset + length > this.bytes.length) {
      throw new ElfError(`range [${offset}, ${offset + length}) out of file (${this.bytes.length} bytes): ${what}`, offset);
    }
    return this.bytes.subarray(offset, offset + length);
  }
}
