/**
 * pdfmeta.js - Metadados do arquivo: paginas, /Info, tamanho da pagina,
 * versao e deteccao de criptografia.
 *
 * Usa a infraestrutura que ja existe (PdfDoc + object streams descomprimidos),
 * sem nenhuma dependencia nova.
 *
 * PRE-REQUISITO: `loadObjectStreams(doc)` precisa ter rodado antes. Em
 * analyze.js isso e garantido porque scanSignaturesFull() ja o chama. Sem
 * isso, tres dos onze PDFs de teste nao teriam nem um unico /Type /Page
 * visivel, porque as paginas estao todas comprimidas.
 */

import { matchString, matchName, parsePdfDate } from './pdfsig.js';

/** Tolerancia em pontos para classificar o formato da pagina. */
const TOLERANCIA_PT = 3;

const FORMATOS = [
  { nome: 'A3', largura: 841.89, altura: 1190.55 },
  { nome: 'A4', largura: 595.28, altura: 841.89 },
  { nome: 'A5', largura: 419.53, altura: 595.28 },
  { nome: 'Carta', largura: 612, altura: 792 },
  { nome: 'Ofício', largura: 612, altura: 1008 },
  { nome: 'Tabloide', largura: 792, altura: 1224 },
];

/**
 * @param {import('./pdfdoc.js').PdfDoc} doc
 * @returns {object} metadados para mesclar em relatorio.arquivo
 */
export function extrairMetadados(doc) {
  const meta = {
    versaoPdf: versaoDoCabecalho(doc),
    cifrado: doc.cifrado,
    paginas: null,
    tamanhoPagina: null,
    formatoPagina: null,
    titulo: null,
    autor: null,
    produtor: null,
    criador: null,
    criadoEm: null,
    modificadoEm: null,
    infoExtra: {},
  };

  // Documento cifrado: strings e streams vem como texto cifrado. Nao adianta
  // tentar ler - o correto e dizer que nao foi possivel, em vez de exibir lixo.
  if (meta.cifrado) return meta;

  const catalogo = corpoDoCatalogo(doc);

  meta.paginas = contarPaginas(doc, catalogo);

  const mediaBox = mediaBoxDaPrimeiraPagina(doc, catalogo);
  if (mediaBox) {
    meta.tamanhoPagina = mediaBox;
    meta.formatoPagina = classificarFormato(mediaBox);
  }

  Object.assign(meta, lerInfo(doc));
  return meta;
}

/** `%PDF-1.x` do inicio do arquivo. */
function versaoDoCabecalho(doc) {
  const m = /%PDF-(\d+\.\d+)/.exec(doc.text.slice(0, 1024));
  return m ? m[1] : null;
}


/** Resolve `/Chave N 0 R` e devolve o corpo do objeto apontado. */
function seguirReferencia(doc, corpo, chave, profundidade = 0) {
  if (!corpo || profundidade > 8) return null;
  const m = new RegExp(`/${chave}\\s+(\\d+)\\s+\\d+\\s*R`).exec(corpo);
  if (!m) return null;
  return doc.bodyOf(Number(m[1]));
}

/**
 * Corpo do Catalog (/Type /Catalog), pela ULTIMA referencia /Root do arquivo.
 *
 * A ultima e a que vale: num PDF com atualizacoes incrementais o mesmo numero
 * de objeto reaparece, e `doc.bodyOf` ja escolhe a revisao de maior offset.
 */
function corpoDoCatalogo(doc) {
  let ultimo = null;
  const re = /\/Root\s+(\d+)\s+\d+\s*R/g;
  let m;
  while ((m = re.exec(doc.text)) !== null) ultimo = Number(m[1]);

  if (ultimo !== null) {
    const corpo = doc.bodyOf(ultimo);
    if (corpo) return corpo;
  }

  // Sem /Root localizavel: procura um /Type /Catalog em qualquer objeto.
  for (const { body } of doc.allBodies()) {
    if (/\/Type\s*\/Catalog/.test(body)) return body;
  }
  return null;
}

/**
 * Numero de paginas.
 *
 * Caminho correto: Catalog -> /Pages -> /Count. Contar ocorrencias de
 * `/Type /Page` nos bytes crus erra em 6 dos 11 arquivos de teste - subconta
 * (zero) quando as paginas estao dentro de object stream, e superconta quando
 * uma revisao incremental regrava um objeto de pagina com o mesmo numero.
 *
 * O fallback conta paginas distintas POR NUMERO DE OBJETO, o que elimina a
 * dupla contagem das revisoes.
 */
function contarPaginas(doc, catalogo) {
  const arvore = seguirReferencia(doc, catalogo, 'Pages');
  if (arvore) {
    const m = /\/Count\s+(\d+)/.exec(arvore);
    if (m) return Number(m[1]);
  }

  const numeros = new Set();
  for (const { num, body } of doc.allBodies()) {
    if (/\/Type\s*\/Page[^s]/.test(body)) numeros.add(num);
  }
  return numeros.size > 0 ? numeros.size : null;
}

/**
 * /MediaBox da primeira pagina, com heranca: se a pagina nao declara, o valor
 * vem do no /Pages acima dela (ISO 32000-1, 7.7.3.4).
 */
function mediaBoxDaPrimeiraPagina(doc, catalogo) {
  const arvore = seguirReferencia(doc, catalogo, 'Pages');
  if (!arvore) return null;

  let corpo = arvore;
  let herdado = lerMediaBox(arvore);

  // Desce pelo primeiro /Kids ate chegar numa folha (/Type /Page).
  for (let nivel = 0; nivel < 32; nivel++) {
    const kids = /\/Kids\s*\[([^\]]*)\]/.exec(corpo);
    if (!kids) break;

    const primeiro = /(\d+)\s+\d+\s*R/.exec(kids[1]);
    if (!primeiro) break;

    const filho = doc.bodyOf(Number(primeiro[1]));
    if (!filho) break;

    corpo = filho;
    herdado = lerMediaBox(corpo) ?? herdado;
    if (/\/Type\s*\/Page[^s]/.test(corpo)) break;
  }

  return herdado;
}

function lerMediaBox(corpo) {
  const m = /\/MediaBox\s*\[\s*([-\d.\s]+?)\s*\]/.exec(corpo);
  if (!m) return null;

  const n = m[1].trim().split(/\s+/).map(Number);
  if (n.length < 4 || n.some((v) => !Number.isFinite(v))) return null;

  const largura = Math.abs(n[2] - n[0]);
  const altura = Math.abs(n[3] - n[1]);
  if (largura <= 0 || altura <= 0) return null;

  return { largura, altura };
}

/**
 * Nome do formato, se casar com um padrao conhecido. A tolerancia existe
 * porque os arquivos reais trazem 595, 595.28, 595.32 e 595.32001 para o
 * mesmo A4.
 */
function classificarFormato({ largura, altura }) {
  const menor = Math.min(largura, altura);
  const maior = Math.max(largura, altura);

  for (const f of FORMATOS) {
    if (
      Math.abs(menor - f.largura) <= TOLERANCIA_PT
      && Math.abs(maior - f.altura) <= TOLERANCIA_PT
    ) {
      return largura > altura ? `${f.nome} paisagem` : f.nome;
    }
  }
  return null;
}

/**
 * Dicionario /Info. A ULTIMA referencia do arquivo e a que vale: num dos PDFs
 * de teste o numero do objeto /Info muda a cada revisao (2, 1280, ... 1408).
 *
 * As strings passam por `matchString` de pdfsig.js, que ja trata literal com
 * parenteses balanceados, escapes octais, hexadecimal e UTF-16BE com BOM -
 * todos presentes no conjunto de teste.
 */
function lerInfo(doc) {
  let ultimo = null;
  const re = /\/Info\s+(\d+)\s+\d+\s*R/g;
  let m;
  while ((m = re.exec(doc.text)) !== null) ultimo = Number(m[1]);
  if (ultimo === null) return {};

  const corpo = doc.bodyOf(ultimo);
  if (!corpo) return {};

  const criado = matchString(corpo, 'CreationDate');
  const modificado = matchString(corpo, 'ModDate');

  return {
    titulo: limpar(matchString(corpo, 'Title')),
    autor: limpar(matchString(corpo, 'Author')),
    produtor: limpar(matchString(corpo, 'Producer')),
    criador: limpar(matchString(corpo, 'Creator')),
    criadoEm: iso(parsePdfDate(criado)),
    modificadoEm: iso(parsePdfDate(modificado)),
    infoExtra: lerChavesNaoPadrao(corpo),
  };
}

/** Chaves do /Info que a ISO 32000-1 nomeia; as demais sao do gerador. */
const INFO_PADRAO = new Set([
  'Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer',
  'CreationDate', 'ModDate', 'Trapped',
]);

/**
 * Chaves fora do conjunto padrao.
 *
 * Enumerar em vez de pedir chave conhecida: metadado personalizado revela a
 * esteira que gerou o arquivo, e e o tipo de coisa que interessa numa
 * auditoria. Num dos PDFs de desenvolvimento aparece `/DocumentKey`, o ID
 * interno do documento na plataforma de assinatura.
 *
 * Nao aparece na tela, so no dump.
 */
function lerChavesNaoPadrao(corpo) {
  const extra = {};

  for (const m of corpo.matchAll(/\/([A-Za-z][A-Za-z0-9_.-]*)/g)) {
    const chave = m[1];
    if (INFO_PADRAO.has(chave) || chave in extra) continue;

    // String literal ou hexadecimal; se nao for, tenta valor de nome (/Key /Val).
    const valor = limpar(matchString(corpo, chave)) ?? matchName(corpo, chave);
    if (valor) extra[chave] = valor;
  }

  return extra;
}

/**
 * Descarta vazios e corta valores absurdamente longos - um dos arquivos de
 * teste guarda o user-agent completo do navegador no campo /Creator.
 * Remove bytes nulos, que sobram quando um UTF-16 e lido byte a byte.
 */
function limpar(valor) {
  if (!valor) return null;
  const s = valor.replace(/\u0000/g, '').trim();
  if (s === '') return null;
  return s.length > 300 ? `${s.slice(0, 297)}...` : s;
}

function iso(data) {
  return data instanceof Date && !isNaN(data) ? data.toISOString() : null;
}
