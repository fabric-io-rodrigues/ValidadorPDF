/**
 * pdfdoc.js - Indice do arquivo PDF, construido uma unica vez e compartilhado
 * por todos os modulos que precisam navegar a estrutura.
 *
 * Existe por dois motivos, ambos de desempenho:
 *
 * 1. A decodificacao do arquivo inteiro era feita quatro vezes.
 *
 * 2. O indice de objetos usava a expressao `/(\d+)\s+(\d+)\s+obj\b/g`. Parece
 *    inocente, mas `\d+` faz backtracking: num PDF real ha longas corridas de
 *    digitos dentro dos streams comprimidos (num dos arquivos de teste, 53.572
 *    digitos seguidos), e o motor tenta cada divisao possivel delas. Medido em
 *    1,5 MB: 6.616 ms com a regex contra 1 ms procurando "obj" literalmente e
 *    lendo os dois numeros de tras para frente. E o mesmo resultado, 6.000x
 *    mais rapido.
 */

import { decodeLatin1 } from './latin1.js';

/** Numero maximo de digitos aceitos num numero de objeto ou geracao. */
const MAX_DIGITS = 10;

export class PdfDoc {
  /** @param {Uint8Array} bytes */
  constructor(bytes) {
    this.bytes = bytes;
    this.text = decodeLatin1(bytes);
    this.objects = indexObjects(this.text);

    /** Ultima versao de cada numero de objeto entre os objetos nao comprimidos. */
    this.latestPlain = new Map();
    for (const obj of this.objects) {
      const previous = this.latestPlain.get(obj.num);
      if (!previous || previous.start < obj.start) this.latestPlain.set(obj.num, obj);
    }

    /** Preenchido por objstm.js: num -> {body, offset}. */
    this.compressed = new Map();

    /** Cache do getter `cifrado`. */
    this._cifrado = undefined;
  }

  /** Contagem de marcas %%EOF, uma por revisao salva. */
  get revisions() {
    return countOccurrences(this.text, '%%EOF');
  }

  /**
   * true se o documento declara criptografia.
   *
   * Vive aqui, e nao em pdfmeta.js, porque quem precisa saber primeiro e a
   * descompressao de object streams: em arquivo cifrado ela nunca funciona.
   *
   * Nao ancora na palavra `trailer`: um dos PDFs de teste e cifrado e nao tem
   * essa palavra em lugar nenhum - usa apenas XRef streams, e o /Encrypt
   * aparece no dicionario de um objeto /Type /XRef.
   */
  get cifrado() {
    if (this._cifrado === undefined) {
      this._cifrado = /\/Encrypt\s+\d+\s+\d+\s*R/.test(this.text);
    }
    return this._cifrado;
  }

  /** Corpo de um objeto nao comprimido. */
  plainBody(obj) {
    return this.text.slice(obj.bodyStart, obj.bodyEnd);
  }

  /**
   * Corpo da versao mais recente de um objeto, comprimido ou nao. Em
   * atualizacao incremental vale a ocorrencia de maior offset - decidir por
   * "cru vence comprimido" erraria quando uma revisao posterior recomprimisse
   * o objeto.
   */
  bodyOf(num) {
    const plain = this.latestPlain.get(num);
    const stream = this.compressed.get(num);

    if (plain && stream) {
      return stream.offset > plain.start ? stream.body : this.plainBody(plain);
    }
    if (plain) return this.plainBody(plain);
    return stream ? stream.body : null;
  }

  /** Objeto nao comprimido que contem o offset informado. */
  objectAt(offset) {
    for (const obj of this.objects) {
      if (offset >= obj.bodyStart && offset < obj.bodyEnd) return obj;
    }
    return null;
  }

  /**
   * Percorre todos os corpos de objeto, comprimidos e nao comprimidos.
   * @returns {Generator<{num: number, body: string}>}
   */
  *allBodies() {
    for (const obj of this.objects) {
      yield { num: obj.num, body: this.plainBody(obj) };
    }
    for (const [num, entry] of this.compressed) {
      yield { num, body: entry.body };
    }
  }
}

/**
 * Localiza "N G obj" varrendo pela palavra "obj" e lendo os numeros de tras
 * para frente. Sem regex, portanto sem backtracking.
 */
export function indexObjects(text) {
  const out = [];
  let i = 0;

  while ((i = text.indexOf('obj', i)) !== -1) {
    const at = i;
    i += 3;

    // "endobj" contem "obj" e nao abre objeto.
    if (at >= 3 && text.startsWith('endobj', at - 3)) continue;

    // Fronteira de palavra a direita: "objx" nao vale.
    if (isAlnum(text.charCodeAt(at + 3))) continue;

    // A esquerda, na ordem: espacos, geracao, espacos, numero.
    let p = skipSpaceBack(text, at - 1);
    const genEnd = p;
    p = skipDigitsBack(text, p);
    if (p === genEnd || genEnd - p > MAX_DIGITS) continue;
    const genStart = p + 1;

    const beforeGen = p;
    p = skipSpaceBack(text, p);
    if (p === beforeGen) continue; // precisa de separador entre os numeros
    const numEnd = p;
    p = skipDigitsBack(text, p);
    if (p === numEnd || numEnd - p > MAX_DIGITS) continue;
    const numStart = p + 1;

    const num = Number(text.slice(numStart, numEnd + 1));
    const gen = Number(text.slice(genStart, genEnd + 1));
    if (!Number.isFinite(num) || !Number.isFinite(gen)) continue;

    const bodyStart = at + 3;
    const endIdx = text.indexOf('endobj', bodyStart);

    out.push({
      num,
      gen,
      start: numStart,
      bodyStart,
      bodyEnd: endIdx === -1 ? text.length : endIdx,
    });
  }

  return out;
}

/** Ultima posicao <= from que nao e espaco em branco. */
function skipSpaceBack(text, from) {
  let p = from;
  while (p >= 0 && isSpace(text.charCodeAt(p))) p--;
  return p;
}

/** Ultima posicao <= from que nao e digito. */
function skipDigitsBack(text, from) {
  let p = from;
  while (p >= 0 && isDigit(text.charCodeAt(p))) p--;
  return p;
}

function isDigit(c) {
  return c >= 48 && c <= 57;
}

function isSpace(c) {
  return c === 32 || c === 10 || c === 13 || c === 9 || c === 0 || c === 12;
}

function isAlnum(c) {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

export function countOccurrences(text, needle) {
  let n = 0;
  let i = 0;
  while ((i = text.indexOf(needle, i)) !== -1) {
    n++;
    i += needle.length;
  }
  return n;
}
