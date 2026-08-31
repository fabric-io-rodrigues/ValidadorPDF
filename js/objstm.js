/**
 * objstm.js - Le objetos indiretos que ficaram dentro de object streams
 * comprimidos (/Type /ObjStm, ISO 32000-1 7.5.7).
 *
 * O dicionario de assinatura em si nunca esta comprimido, mas o campo de
 * formulario que o referencia (/FT /Sig com o /T) normalmente esta. Sem ler os
 * ObjStm, o nome do campo fica invisivel - e, mais importante, nao ha como
 * saber se a assinatura esta registrada no /AcroForm atual ou se ficou orfa de
 * uma revisao anterior.
 *
 * Usa DecompressionStream, nativo em navegadores atuais e no Node 18+, sem
 * dependencia externa. Onde ele nao existir, o enriquecimento e perdido em
 * silencio e o resto da analise continua valido.
 */

const LATIN1 = new TextDecoder('latin1');

/**
 * Descomprime os object streams e preenche `doc.compressed`.
 *
 * Numa atualizacao incremental o mesmo numero de objeto aparece varias vezes;
 * guardamos o offset de cada ocorrencia para que `doc.bodyOf` escolha a mais
 * recente, que e a que o leitor de PDF usa.
 *
 * @param {import('./pdfdoc.js').PdfDoc} doc
 */
export async function loadObjectStreams(doc) {
  // Em PDF cifrado o stream e cifrado ANTES de comprimido, entao o inflate
  // nunca tem como funcionar. Sair aqui evita percorrer todos os object
  // streams do arquivo para falhar em cada um.
  if (doc.cifrado) return doc.compressed;

  for (const obj of doc.objects) {
    const streamIdx = doc.text.indexOf('stream', obj.bodyStart);
    if (streamIdx === -1 || streamIdx > obj.bodyEnd) continue;

    const dict = doc.text.slice(obj.bodyStart, streamIdx);
    if (!/\/Type\s*\/ObjStm/.test(dict)) continue;
    // Filtros exoticos (LZW, encriptacao, cadeias de filtros) ficam de fora.
    if (!/\/Filter\s*\/FlateDecode/.test(dict)) continue;

    const n = intOf(dict, 'N');
    const first = intOf(dict, 'First');
    const length = intOf(dict, 'Length');
    if (n === null || first === null) continue;

    // Apos "stream" vem CRLF ou LF antes dos dados.
    let dataStart = streamIdx + 'stream'.length;
    if (doc.text[dataStart] === '\r') dataStart++;
    if (doc.text[dataStart] === '\n') dataStart++;

    const dataEnd = length !== null
      ? dataStart + length
      : doc.text.indexOf('endstream', dataStart);
    if (dataEnd <= dataStart || dataEnd > doc.bytes.length) continue;

    let inflated;
    try {
      inflated = await inflate(doc.bytes.subarray(dataStart, dataEnd));
    } catch {
      continue; // stream corrompido, cifrado ou filtro encadeado
    }

    for (const [num, body] of splitObjStm(LATIN1.decode(inflated), n, first)) {
      const previous = doc.compressed.get(num);
      if (!previous || previous.offset < obj.start) {
        doc.compressed.set(num, { body, offset: obj.start });
      }
    }
  }
  return doc.compressed;
}

/**
 * O ObjStm comeca com N pares "objnum offset" e, a partir de /First, os corpos
 * concatenados. O offset de cada objeto e relativo a /First.
 */
function splitObjStm(content, n, first) {
  const numbers = content.slice(0, first).trim().split(/\s+/).map(Number);
  const entries = [];

  for (let i = 0; i < n; i++) {
    const num = numbers[i * 2];
    const offset = numbers[i * 2 + 1];
    if (!Number.isFinite(num) || !Number.isFinite(offset)) continue;

    const nextOffset = i + 1 < n ? numbers[(i + 1) * 2 + 1] : null;
    const start = first + offset;
    const end = Number.isFinite(nextOffset) ? first + nextOffset : content.length;
    entries.push([num, content.slice(start, Math.min(end, content.length))]);
  }
  return entries;
}

async function inflate(data) {
  // PDF FlateDecode e zlib com cabecalho; se o cabecalho estiver ausente
  // (gerador fora de spec), tenta deflate cru.
  try {
    return await runStream(data, 'deflate');
  } catch {
    return await runStream(data, 'deflate-raw');
  }
}

async function runStream(data, format) {
  const stream = new DecompressionStream(format);
  const writer = stream.writable.getWriter();

  /*
   * `write` e `close` devolvem promessa, e quando o stream falha as duas
   * rejeitam. Ignora-las cria rejeicao nao tratada: no Node isso derruba o
   * processo, no navegador vira erro solto no console que ninguem captura -
   * mesmo com try/catch em volta, porque o try pega a rejeicao do reader, nao
   * a do writer.
   *
   * Acontece de verdade: num PDF cifrado o stream e cifrado antes de
   * comprimido, o inflate falha com Z_DATA_ERROR, e as duas promessas rejeitam.
   *
   * `catch(() => {})` aqui e correto e nao esconde nada: o erro real chega pelo
   * `reader.read()` abaixo, que esta dentro do try de quem chama.
   */
  const escrita = writer.write(data).catch(() => {});
  const fechamento = writer.close().catch(() => {});

  const chunks = [];
  const reader = stream.readable.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    await Promise.allSettled([escrita, fechamento]);
  }

  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

function intOf(dict, key) {
  const m = new RegExp(`/${key}\\s+(\\d+)`).exec(dict);
  return m ? Number(m[1]) : null;
}
