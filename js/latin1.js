/**
 * latin1.js - Decodificacao byte a byte.
 *
 * `new TextDecoder('latin1')` nao e ISO-8859-1. Pelo padrao WHATWG os rotulos
 * `latin1`, `iso-8859-1` e `l1` todos mapeiam para windows-1252, que troca os
 * 32 bytes de 0x80 a 0x9F por outros pontos de codigo:
 *
 *   0x82 -> U+201A     0x98 -> U+02DC     0x8C -> U+0152
 *
 * O comprimento da string continua igual ao numero de bytes, entao os offsets
 * nunca erram, mas `charCodeAt(i) & 0xff` deixa de devolver o byte original.
 * Num PDF de 1,4 MB isso atinge 140 mil bytes.
 *
 * Importa porque o projeto trata `PdfDoc.text` como o arquivo em forma de
 * string e extrai binario dela - o DER do certificado em /Cert, por exemplo.
 */

/** Tamanho do bloco: abaixo do limite de argumentos de `apply`. */
const BLOCO = 0x8000;

/** @param {Uint8Array} bytes @returns {string} um caractere por byte */
export function decodeLatin1(bytes) {
  if (bytes.length <= BLOCO) return String.fromCharCode.apply(null, bytes);

  const partes = [];
  for (let i = 0; i < bytes.length; i += BLOCO) {
    partes.push(String.fromCharCode.apply(null, bytes.subarray(i, i + BLOCO)));
  }
  return partes.join('');
}
