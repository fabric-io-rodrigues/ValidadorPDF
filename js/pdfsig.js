/**
 * pdfsig.js - Localiza dicionarios de assinatura dentro do PDF e analisa
 * a cobertura do /ByteRange.
 *
 * Nao usa parser de PDF completo, e isso e proposital. Pela especificacao
 * (ISO 32000-1, 12.8.1) o dicionario de assinatura nao pode estar dentro de um
 * object stream comprimido, porque o /ByteRange precisa apontar para offsets
 * fisicos do arquivo. Logo, varrer os bytes crus encontra todas as assinaturas
 * - inclusive as que ficaram orfas de revisoes anteriores e que um leitor
 * baseado em AcroForm/xref deixa de enumerar.
 */

import { PdfDoc } from './pdfdoc.js';
import { loadObjectStreams } from './objstm.js';

const LATIN1 = new TextDecoder('latin1');

/** Classificacao da cobertura do /ByteRange. */
export const COBERTURA = {
  ARQUIVO_INTEIRO: 'ARQUIVO_INTEIRO',
  REVISAO_ANTERIOR: 'REVISAO_ANTERIOR',
  COBERTURA_PARCIAL: 'COBERTURA_PARCIAL',
  ALEM_DO_FIM: 'ALEM_DO_FIM',
};

/** Uma assinatura encontrada no arquivo, ainda sem verificacao criptografica. */
export class PdfSignature {
  constructor(fields) {
    Object.assign(this, fields);
  }

  /**
   * Bytes efetivamente cobertos pela assinatura, na ordem do /ByteRange.
   * Se o /ByteRange apontar para fora do arquivo, o que existe e devolvido e a
   * diferenca aparece em `coverage` - e dela que sai o diagnostico correto.
   */
  signedBytes(fileBytes) {
    const parts = [];
    for (let i = 0; i + 1 < this.byteRange.length; i += 2) {
      const offset = Math.min(this.byteRange[i], fileBytes.length);
      const end = Math.min(offset + this.byteRange[i + 1], fileBytes.length);
      parts.push(fileBytes.subarray(offset, end));
    }
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let pos = 0;
    for (const p of parts) {
      out.set(p, pos);
      pos += p.length;
    }
    return out;
  }
}

/**
 * Varredura completa. Recebe (ou cria) o indice do documento, acha as
 * assinaturas e complementa o que exige descomprimir object streams.
 *
 * @param {Uint8Array|PdfDoc} input
 * @param {(etapa: string) => void} [onProgresso]
 */
export async function scanSignaturesFull(input, onProgresso = () => {}) {
  const doc = input instanceof PdfDoc ? input : new PdfDoc(input);

  onProgresso('localizando assinaturas');
  const signatures = scanSignatures(doc);
  if (signatures.length === 0) return { doc, signatures };

  onProgresso('descomprimindo estrutura do documento');
  try {
    await loadObjectStreams(doc);
  } catch {
    /* segue sem o enriquecimento */
  }

  onProgresso('resolvendo campos de formulário');
  const registrados = collectAcroFormFields(doc);

  for (const sig of signatures) {
    if (sig.objectNumber === null) continue;

    const holder = findFieldObject(doc, sig.objectNumber);
    if (holder) {
      sig.fieldObject = holder.num;
      if (!sig.fieldName) sig.fieldName = fieldNameOf(doc, holder.body);
    }

    // null = nao foi possivel determinar. Melhor do que afirmar "orfa" a esmo.
    sig.registradoNoAcroForm = registrados
      ? registrados.has(sig.fieldObject ?? sig.objectNumber)
      : null;
  }

  return { doc, signatures };
}

/**
 * Varredura sincrona pelos bytes crus. Ancora na chave /ByteRange: toda
 * assinatura PDF a tem, e ela e o que permite reconstruir o que foi assinado.
 *
 * @param {PdfDoc} doc
 */
export function scanSignatures(doc) {
  const { text, bytes } = doc;
  const found = [];
  const byteRangeRe = /\/ByteRange\s*\[([^\]]{0,200})\]/g;
  let m;

  while ((m = byteRangeRe.exec(text)) !== null) {
    const byteRange = m[1].trim().split(/\s+/).map(Number);
    if (byteRange.length < 4 || byteRange.some((n) => !Number.isFinite(n))) continue;

    const owner = doc.objectAt(m.index);
    const scopeStart = owner ? owner.bodyStart : Math.max(0, m.index - 4096);
    const scopeEnd = owner ? owner.bodyEnd : Math.min(text.length, m.index + 65536);
    const scope = text.slice(scopeStart, scopeEnd);

    const contents = findContents(text, scopeStart, scopeEnd);
    if (!contents) continue;

    found.push(
      new PdfSignature({
        objectNumber: owner ? owner.num : null,
        dictOffset: scopeStart,
        byteRange,
        contentsStart: contents.start,
        contentsEnd: contents.end,
        cms: hexToBytes(contents.hex),
        subFilter: matchName(scope, 'SubFilter'),
        filter: matchName(scope, 'Filter'),
        sigType: matchName(scope, 'Type') === 'DocTimeStamp' ? 'DocTimeStamp' : 'Sig',
        declaredName: matchString(scope, 'Name'),
        reason: matchString(scope, 'Reason'),
        location: matchString(scope, 'Location'),
        contactInfo: matchString(scope, 'ContactInfo'),
        dictDate: parsePdfDate(matchString(scope, 'M')),
        fieldName: matchString(scope, 'T'),
        coverage: analyseCoverage(byteRange, contents, bytes.length, text),
      }),
    );
  }

  return found.sort((a, b) => a.dictOffset - b.dictOffset);
}

/**
 * Acha o /Contents <hex> dentro do escopo. Precisamos dos offsets exatos do
 * literal hexadecimal para conferir se ele coincide com a lacuna do /ByteRange.
 */
function findContents(text, scopeStart, scopeEnd) {
  const re = /\/Contents\s*<([0-9a-fA-F\s]*)>/g;
  re.lastIndex = scopeStart;
  let m;

  while ((m = re.exec(text)) !== null) {
    if (m.index >= scopeEnd) break;
    const hex = m[1].replace(/\s+/g, '');
    if (hex.length < 40) continue; // placeholder vazio

    const openOffset = m[0].indexOf('<');
    const open = m.index + openOffset;
    return { hex, start: open, end: m.index + m[0].length };
  }
  return null;
}

/**
 * Analisa se o /ByteRange cobre o arquivo e se a lacuna corresponde exatamente
 * ao literal /Contents. Divergencia aqui indica assinatura remontada ou
 * documento reconstruido depois de assinado.
 */
function analyseCoverage(byteRange, contents, fileLength, text) {
  const notes = [];

  // O fim coberto e o maior (offset + comprimento) entre todos os pares. Usar
  // so o segundo par subestimaria a cobertura num /ByteRange de 3+ pares.
  let coveredEnd = 0;
  for (let i = 0; i + 1 < byteRange.length; i += 2) {
    coveredEnd = Math.max(coveredEnd, byteRange[i] + byteRange[i + 1]);
  }

  if (byteRange[0] !== 0) notes.push('o /ByteRange não começa no byte 0 do arquivo');

  // A lacuna deve ser exatamente o literal <...> do /Contents. So da para
  // afirmar isso na forma usual de dois pares.
  let gapMatchesContents = null;
  if (byteRange.length === 4) {
    const gapStart = byteRange[0] + byteRange[1];
    const gapEnd = byteRange[2];
    gapMatchesContents = gapStart === contents.start && gapEnd === contents.end;
    if (!gapMatchesContents) {
      notes.push(
        'a lacuna do /ByteRange não coincide com a posição do literal /Contents '
        + `(a assinatura esperava a lacuna em ${gapStart}..${gapEnd}, mas ela está `
        + `em ${contents.start}..${contents.end})`,
      );
    }
  } else {
    notes.push(`o /ByteRange tem ${Math.floor(byteRange.length / 2)} intervalos, fora da forma usual de 2`);
  }

  // Caso mais grave: a area assinada termina depois do fim do arquivo. O
  // documento assinado era maior do que este; foi truncado ou reconstruido.
  if (coveredEnd > fileLength) {
    return {
      level: COBERTURA.ALEM_DO_FIM,
      coveredEnd,
      bytesAfter: 0,
      bytesFaltando: coveredEnd - fileLength,
      fileLength,
      gapMatchesContents,
      notes,
    };
  }

  const bytesAfter = fileLength - coveredEnd;
  let level;

  if (bytesAfter === 0) {
    level = COBERTURA.ARQUIVO_INTEIRO;
  } else {
    // Sobra apos a area assinada: normal numa atualizacao incremental valida
    // (outra assinatura, ou um /DSS com dados de validacao), suspeito se for
    // lixo solto.
    const tail = text.slice(coveredEnd, coveredEnd + 4096);
    const looksIncremental = /(\d[\s\r\n]+\d[\s\r\n]+obj|xref|trailer|%%EOF)/.test(tail);
    level = looksIncremental ? COBERTURA.REVISAO_ANTERIOR : COBERTURA.COBERTURA_PARCIAL;
    if (!looksIncremental) {
      notes.push(
        `os ${bytesAfter} bytes após a área assinada não tem a forma de uma `
        + 'atualização incremental de PDF',
      );
    }
  }

  return {
    level,
    coveredEnd,
    bytesAfter,
    bytesFaltando: 0,
    fileLength,
    gapMatchesContents,
    notes,
  };
}

/** Acha o objeto de campo de formulario cujo /V aponta para o dicionario. */
function findFieldObject(doc, sigObjNum) {
  const ref = new RegExp(`/V\\s+${sigObjNum}\\s+\\d+\\s+R`);
  for (const entry of doc.allBodies()) {
    if (ref.test(entry.body)) return entry;
  }
  return null;
}

/** Nome do campo, subindo a cadeia de /Parent quando o filho nao tem /T. */
function fieldNameOf(doc, body, depth = 0) {
  const own = matchString(body, 'T');
  if (own) return own;
  if (depth > 8) return null;

  const parent = /\/Parent\s+(\d+)\s+\d+\s+R/.exec(body);
  if (!parent) return null;
  const parentBody = doc.bodyOf(Number(parent[1]));
  return parentBody ? fieldNameOf(doc, parentBody, depth + 1) : null;
}

/**
 * Numeros de objeto alcancaveis a partir do /AcroForm /Fields mais recente,
 * seguindo /Kids. Devolve null se o AcroForm nao for localizavel, para que o
 * relatorio diga "indeterminado" em vez de "não registrado".
 */
function collectAcroFormFields(doc) {
  const pattern = /\/AcroForm\s*(?:(\d+)\s+\d+\s+R|<<)/;
  const candidates = [];

  const global = new RegExp(pattern.source, 'g');
  let m;
  while ((m = global.exec(doc.text)) !== null) {
    candidates.push({ ref: m[1], at: m.index, body: doc.text, offset: m.index });
  }
  for (const [, entry] of doc.compressed) {
    const cm = pattern.exec(entry.body);
    if (cm) candidates.push({ ref: cm[1], at: cm.index, body: entry.body, offset: entry.offset });
  }
  if (candidates.length === 0) return null;

  // Vale o Catalog mais recente do arquivo, pela mesma razao dos objetos.
  candidates.sort((a, b) => a.offset - b.offset);
  const chosen = candidates[candidates.length - 1];

  const acroBody = chosen.ref
    ? doc.bodyOf(Number(chosen.ref))
    : chosen.body.slice(chosen.at, chosen.at + 4096);
  if (!acroBody) return null;

  const fieldsMatch = /\/Fields\s*\[([^\]]*)\]/.exec(acroBody);
  if (!fieldsMatch) return null;

  const out = new Set();
  const queue = [...fieldsMatch[1].matchAll(/(\d+)\s+\d+\s+R/g)].map((x) => Number(x[1]));

  while (queue.length) {
    const num = queue.shift();
    if (out.has(num)) continue;
    out.add(num);

    const body = doc.bodyOf(num);
    if (!body) continue;
    const kids = /\/Kids\s*\[([^\]]*)\]/.exec(body);
    if (kids) {
      for (const k of kids[1].matchAll(/(\d+)\s+\d+\s+R/g)) queue.push(Number(k[1]));
    }
  }
  return out;
}

export function matchName(scope, key) {
  const m = new RegExp(`/${key}\\s*/([A-Za-z0-9.\\-_]+)`).exec(scope);
  return m ? m[1] : null;
}

/**
 * String de PDF: literal entre parenteses ou hexadecimal entre <>.
 * Trata escapes de barra invertida e o BOM UTF-16BE.
 */
export function matchString(scope, key) {
  const m = new RegExp(`/${key}\\s*(\\(|<)`).exec(scope);
  if (!m) return null;

  const open = m.index + m[0].length - 1;
  if (scope[open] === '<') {
    const close = scope.indexOf('>', open);
    if (close === -1) return null;
    const hex = scope.slice(open + 1, close).replace(/\s+/g, '');
    if (hex.length === 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
    return decodePdfText(hexToBytes(hex));
  }

  // Literal: conta parenteses balanceados, respeitando escapes.
  let depth = 1;
  let out = '';
  for (let i = open + 1; i < scope.length; i++) {
    const ch = scope[i];
    if (ch === '\\') {
      const next = scope[i + 1];
      const simple = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' };
      if (next in simple) { out += simple[next]; i++; } else if (/[0-7]/.test(next)) {
        const oct = /^[0-7]{1,3}/.exec(scope.slice(i + 1))[0];
        out += String.fromCharCode(parseInt(oct, 8));
        i += oct.length;
      } else { out += next; i++; }
      continue;
    }
    if (ch === '(') depth++;
    if (ch === ')') { depth--; if (depth === 0) break; }
    out += ch;
  }
  return decodePdfText(Uint8Array.from(out, (c) => c.charCodeAt(0) & 0xff));
}

/** Texto de PDF: UTF-16BE se tiver BOM FE FF, senao PDFDocEncoding ~ latin1. */
function decodePdfText(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let s = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return s;
  }
  return LATIN1.decode(bytes);
}

/** Data de PDF: D:YYYYMMDDHHmmSSOHH'mm' */
export function parsePdfDate(value) {
  if (!value) return null;
  const m = /D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:(Z|[+-])(\d{2})'?(\d{2})?)?/.exec(value);
  if (!m) return null;

  let ms = Date.UTC(
    +m[1], (+(m[2] || 1)) - 1, +(m[3] || 1),
    +(m[4] || 0), +(m[5] || 0), +(m[6] || 0),
  );
  if (m[7] && m[7] !== 'Z') {
    const sign = m[7] === '-' ? 1 : -1;
    ms += sign * ((+m[8]) * 60 + (+(m[9] || 0))) * 60000;
  }
  return new Date(ms);
}

function hexToBytes(hex) {
  // O /Contents costuma vir preenchido com zeros a direita ate o tamanho
  // reservado; o parser DER simplesmente ignora o excedente.
  const clean = hex.length % 2 ? hex.slice(0, -1) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}
