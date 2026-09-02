/**
 * der.js - Parser DER/BER minimo (TLV) para ASN.1.
 *
 * Escopo deliberadamente pequeno: o suficiente para navegar CMS/PKCS#7 e X.509.
 * Trabalha sempre sobre fatias (subarray) do buffer original, sem copiar, porque
 * a verificacao criptografica exige os bytes exatos como estavam no arquivo.
 *
 * Suporta comprimento indefinido (BER), que aparece em conteineres PKCS#7 de
 * algumas ferramentas Adobe e faz bibliotecas estritas falharem.
 */

export const UNIVERSAL = 0;
export const CONTEXT = 2;

export const TAG = {
  BOOLEAN: 1, INTEGER: 2, BIT_STRING: 3, OCTET_STRING: 4, NULL: 5,
  OID: 6, UTF8_STRING: 12, SEQUENCE: 16, SET: 17, NUMERIC_STRING: 18,
  PRINTABLE_STRING: 19, T61_STRING: 20, IA5_STRING: 22, UTC_TIME: 23,
  GENERALIZED_TIME: 24, BMP_STRING: 30,
};

const MAX_DEPTH = 40;

export class DerError extends Error {}

/** Um no TLV. `bytes` = TLV completo; `content` = apenas o valor. */
export class Node {
  constructor(buf, start, headerLen, contentLen, cls, constructed, tagNo, indefinite) {
    this.buf = buf;
    this.start = start;
    this.headerLen = headerLen;
    this.contentStart = start + headerLen;
    this.contentLen = contentLen;
    this.contentEnd = this.contentStart + contentLen;
    this.end = indefinite ? this.contentEnd + 2 : this.contentEnd;
    this.cls = cls;
    this.constructed = constructed;
    this.tagNo = tagNo;
    this.indefinite = indefinite;
    this._children = null;
  }

  get bytes() { return this.buf.subarray(this.start, this.end); }
  get content() { return this.buf.subarray(this.contentStart, this.contentEnd); }

  /** true se for o tag universal informado (SEQUENCE, SET, OID...). */
  is(tagNo) { return this.cls === UNIVERSAL && this.tagNo === tagNo; }

  /** true se for [n] do context class (campos IMPLICIT/EXPLICIT). */
  isContext(n) { return this.cls === CONTEXT && this.tagNo === n; }

  get children() {
    if (this._children === null) {
      this._children = this.constructed
        ? parseSequence(this.buf, this.contentStart, this.contentEnd)
        : [];
    }
    return this._children;
  }

  at(i) { return this.children[i]; }

  /** Primeiro filho [n] do context class, ou undefined. */
  context(n) { return this.children.find((c) => c.isContext(n)); }

  /** Percorre a subarvore, inclusive este no. */
  *descendants(depth = 0) {
    yield this;
    if (depth > MAX_DEPTH) return;
    for (const c of this.children) yield* c.descendants(depth + 1);
  }
}

/** Le um unico TLV a partir de `pos`. */
export function readTLV(buf, pos, limit = buf.length) {
  const start = pos;
  if (pos >= limit) throw new DerError('fim inesperado dos dados ASN.1');

  const identifier = buf[pos++];
  const cls = identifier >> 6;
  const constructed = (identifier & 0x20) !== 0;
  let tagNo = identifier & 0x1f;

  if (tagNo === 0x1f) {
    tagNo = 0;
    let c;
    do {
      if (pos >= limit) throw new DerError('tag de multiplos bytes truncada');
      c = buf[pos++];
      tagNo = tagNo * 128 + (c & 0x7f);
    } while (c & 0x80);
  }

  if (pos >= limit) throw new DerError('comprimento ausente');
  const lenByte = buf[pos++];
  let contentLen;
  let indefinite = false;

  if (lenByte === 0x80) {
    if (!constructed) throw new DerError('comprimento indefinido em tipo primitivo');
    indefinite = true;
    contentLen = scanIndefinite(buf, pos, limit);
  } else if (lenByte & 0x80) {
    const n = lenByte & 0x7f;
    if (n > 4) throw new DerError('comprimento de ' + n + ' bytes nao suportado');
    contentLen = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= limit) throw new DerError('comprimento truncado');
      contentLen = contentLen * 256 + buf[pos++];
    }
  } else {
    contentLen = lenByte;
  }

  const headerLen = pos - start;
  if (start + headerLen + contentLen > limit) {
    throw new DerError('conteudo declarado excede o buffer');
  }
  return new Node(buf, start, headerLen, contentLen, cls, constructed, tagNo, indefinite);
}

/** Mede o conteudo de um TLV de comprimento indefinido, ate o EOC (00 00). */
function scanIndefinite(buf, pos, limit) {
  const begin = pos;
  while (pos < limit) {
    if (buf[pos] === 0x00 && buf[pos + 1] === 0x00) return pos - begin;
    pos = readTLV(buf, pos, limit).end;
  }
  throw new DerError('EOC nao encontrado (comprimento indefinido)');
}

/** Le TLVs consecutivos no intervalo [start, end). */
export function parseSequence(buf, start, end) {
  const out = [];
  let pos = start;
  while (pos < end) {
    if (buf[pos] === 0x00 && buf[pos + 1] === 0x00) break; // EOC
    const node = readTLV(buf, pos, end);
    if (node.end <= pos) throw new DerError('TLV de tamanho zero (loop)');
    out.push(node);
    pos = node.end;
  }
  return out;
}

/** Ponto de entrada: parseia o primeiro TLV de um buffer. */
export function parse(bytes) {
  return readTLV(bytes, 0, bytes.length);
}

// ---------------------------------------------------------------- decodificadores

/**
 * OID no formato pontilhado. O primeiro byte codifica dois arcos como
 * 40*X + Y, com X em {0,1,2} e Y ilimitado quando X = 2.
 */
export function decodeOID(node) {
  const c = node.content;
  if (c.length === 0) return '';

  const first = c[0];
  const arc1 = first < 40 ? 0 : first < 80 ? 1 : 2;
  const parts = [String(arc1), String(first - arc1 * 40)];

  let value = 0n;
  let pending = false;
  for (let i = 1; i < c.length; i++) {
    value = (value << 7n) | BigInt(c[i] & 0x7f);
    pending = true;
    if (!(c[i] & 0x80)) {
      parts.push(value.toString());
      value = 0n;
      pending = false;
    }
  }
  if (pending) throw new DerError('OID truncado');
  return parts.join('.');
}

/** INTEGER como BigInt, com sinal (dois complementos), como manda o DER. */
export function decodeInteger(node) {
  const c = node.content;
  if (c.length === 0) return 0n;
  let v = 0n;
  for (const byte of c) v = (v << 8n) | BigInt(byte);
  if (c[0] & 0x80) v -= 1n << BigInt(8 * c.length);
  return v;
}

/** Serial de certificado: hexadecimal minusculo, sem sinal, em pares de digitos. */
export function serialToHex(node) {
  let hex = toHex(node.content).replace(/^(?:00)+(?=..)/, '');
  if (hex.length % 2) hex = '0' + hex;
  return hex || '00';
}

import { decodeLatin1 } from './latin1.js';

const UTF8 = new TextDecoder('utf-8');
/* asn1crypto decodifica T61String e afins como ISO-8859-1 de verdade. */

/** String ASN.1 respeitando o tag. BMPString e UTF-16BE. */
export function decodeString(node) {
  const c = node.content;
  if (node.tagNo === TAG.BMP_STRING) {
    let s = '';
    for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]);
    return s;
  }
  if (node.tagNo === TAG.UTF8_STRING) return UTF8.decode(c);
  // PrintableString/IA5String sao ASCII; T61 e afins cabem em ISO-8859-1.
  return decodeLatin1(c);
}

/**
 * UTCTime / GeneralizedTime -> Date.
 * UTCTime tem ano de 2 digitos: >= 50 vira 19xx (RFC 5280 4.1.2.5.1).
 */
export function decodeTime(node) {
  const s = decodeLatin1(node.content).trim();
  const m = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{4})?$/.exec(s);
  if (!m) return null;

  let year = parseInt(m[1], 10);
  if (m[1].length === 2) year += year >= 50 ? 1900 : 2000;
  const millis = m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0;

  let ms = Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0), millis);
  const tz = m[8];
  if (tz && tz !== 'Z') {
    const sign = tz[0] === '-' ? 1 : -1;
    ms += sign * (parseInt(tz.slice(1, 3), 10) * 60 + parseInt(tz.slice(3, 5), 10)) * 60000;
  }
  return new Date(ms);
}

/** Conteudo de um BIT STRING, descartando o byte de bits nao usados. */
export function bitStringBytes(node) {
  return node.content.subarray(1);
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
