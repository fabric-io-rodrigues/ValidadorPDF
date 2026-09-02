/**
 * analyze.js - Orquestra a analise de um PDF e devolve o relatorio completo.
 *
 * Nao toca no DOM de proposito: roda dentro de um Web Worker, e o resultado e
 * um objeto de dados puro - sem frase montada, sem interpretacao. Quem exibe
 * decide como dizer.
 */

import { PdfDoc } from './pdfdoc.js';
import { scanSignaturesFull, COBERTURA } from './pdfsig.js';
import { readSignedData } from './cms.js';
import { ehPkcs1, lerPkcs1 } from './pkcs1.js';
import { extractIdentity, classifyIssuer } from './icpbrasil.js';
import { verifySignerInfo, verifyTimestampImprint, checkValidity, sha256Hex } from './verify.js';
import { validarCadeia } from './trust.js';
import { CONTENT_TYPES } from './oid.js';
import { extrairMetadados } from './pdfmeta.js';

export const VERSAO = '1.2';

/**
 * @param {Uint8Array} bytes conteudo do PDF
 * @param {string} nomeArquivo apenas para o relatorio
 * @param {(etapa: string) => void} [onProgresso]
 */
export async function analisarPdf(bytes, nomeArquivo, onProgresso = () => {}) {
  onProgresso('calculando hash do arquivo');

  const relatorio = {
    versao: VERSAO,
    arquivo: {
      nome: nomeArquivo,
      tamanho: bytes.length,
      sha256: await sha256Hex(bytes),
      revisoes: 0,
      pdf: isPdf(bytes),
    },
    assinado: false,
    totalAssinaturas: 0,
    assinaturas: [],
    alertas: [],
    erro: null,
  };

  if (!relatorio.arquivo.pdf) {
    relatorio.erro = 'o arquivo não começa com a assinatura %PDF-';
    return relatorio;
  }

  let encontradas;
  let doc;
  try {
    onProgresso('indexando a estrutura do PDF');
    doc = new PdfDoc(bytes);
    relatorio.arquivo.revisoes = doc.revisions;

    const resultado = await scanSignaturesFull(doc, onProgresso);
    encontradas = resultado.signatures;

    // Depois da varredura: scanSignaturesFull ja rodou loadObjectStreams, e
    // sem isso tres dos PDFs de teste nao teriam nenhuma pagina visivel.
    onProgresso('lendo metadados do documento');
    Object.assign(relatorio.arquivo, extrairMetadados(doc));
  } catch (err) {
    relatorio.erro = `falha ao varrer a estrutura do PDF: ${err.message}`;
    return relatorio;
  }

  relatorio.totalAssinaturas = encontradas.length;
  relatorio.assinado = encontradas.length > 0;

  for (let i = 0; i < encontradas.length; i++) {
    onProgresso(`verificando assinatura ${i + 1} de ${encontradas.length}`);
    relatorio.assinaturas.push(await analisarAssinatura(encontradas[i], i + 1, bytes));
  }

  relatorio.alertas = montarAlertas(relatorio);
  return relatorio;
}

async function analisarAssinatura(sig, indice, fileBytes) {
  const item = {
    indice,
    campo: sig.fieldName,
    objeto: sig.objectNumber,
    campoObjeto: sig.fieldObject ?? null,
    registradoNoAcroForm: sig.registradoNoAcroForm ?? null,
    tipo: sig.sigType,
    subFilter: sig.subFilter,
    motivo: sig.reason,
    local: sig.location,
    contato: sig.contactInfo,
    nomeDeclarado: sig.declaredName,
    cobertura: sig.coverage,
    signatario: null,
    certificado: null,
    cadeia: [],
    confianca: null,
    datas: {
      declaradaNoDicionario: iso(sig.dictDate),
      signingTimeAtributo: null,
      carimboDoTempo: null,
    },
    cripto: null,
    diagnostico: null,
    erro: null,
  };

  const signedBytes = sig.signedBytes(fileBytes);

  // Estrutura crua antes de qualquer leitura que possa falhar: se o conteiner
  // for ilegivel, o dump ainda mostra onde a assinatura esta no arquivo.
  item.byteRange = sig.byteRange;
  item.contents = {
    inicio: sig.contentsStart,
    fim: sig.contentsEnd,
    tamanhoAssinatura: sig.cms.length,
  };

  const leitura = ehPkcs1(sig.subFilter)
    ? await lerPkcs1(sig, signedBytes)
    : await lerCms(sig, signedBytes);

  if (leitura.erro) {
    item.erro = leitura.erro;
    item.diagnostico = leitura.diagnostico ?? null;
    return item;
  }

  const { cert, certificados } = leitura;

  item.formato = leitura.formato;
  item.cripto = leitura.cripto;
  item.cripto.bytesConferidos = signedBytes.length;
  if (leitura.cms) item.cms = leitura.cms;
  if (leitura.cossignatarios > 1) item.cossignatarios = leitura.cossignatarios;
  Object.assign(item.datas, leitura.datas);

  const dataReferencia =
    dateOf(item.datas.carimboDoTempo?.genTime) ??
    leitura.signingTime ??
    sig.dictDate ??
    null;

  if (cert) {
    const origem = classifyIssuer(cert);
    const identidade = extractIdentity(cert);

    item.signatario = {
      ...identidade,
      ...origem,
      // Ordem de preferencia para o nome exibido: responsavel ICP-Brasil,
      // titular do CN, nome declarado no dicionario do PDF.
      nomeExibicao: identidade.nomeTitular || sig.declaredName || cert.commonName || null,
    };

    item.certificado = {
      subject: cert.subjectHumanFriendly,
      issuer: cert.issuerHumanFriendly,
      commonName: cert.commonName,
      serieHex: `0x${cert.serialNumberHex}`,
      notBefore: iso(cert.notBefore),
      notAfter: iso(cert.notAfter),
      vigencia: serializeValidity(checkValidity(cert, dataReferencia)),
      politicas: cert.policies,
      usoDaChave: cert.keyUsage,
      algoritmoChave: cert.publicKeyAlgorithm.name ?? cert.publicKeyAlgorithm.oid,
      sanBrutos: identidade.camposBrutos,

      // Para o dump: tudo que o certificado declara, nao so o que a pagina usa.
      versao: cert.version,
      subjectKeyId: cert.subjectKeyId,
      authorityKeyId: cert.authorityKeyId,
      autoAssinado: cert.selfIssued,
      extensoes: cert.extensions.map((e) => ({
        oid: e.oid,
        nome: e.name,
        critical: e.critical,
      })),
      sanTodos: cert.subjectAltNames.map((n) => ({
        tipo: n.type,
        typeId: n.typeId ?? null,
        nome: n.typeName ?? null,
        valor: n.value,
      })),
    };
  }

  item.datas.confiabilidade = avaliarData(item.datas, cert);

  item.cadeia = certificados.map((c) => ({
    commonName: c.commonName,
    subject: c.subjectHumanFriendly,
    issuer: c.issuerHumanFriendly,
    serieHex: `0x${c.serialNumberHex}`,
    autoridadeCertificadora: c.isCA,
    signatario: cert ? c.serialNumberHex === cert.serialNumberHex : false,
    notBefore: iso(c.notBefore),
    notAfter: iso(c.notAfter),
  }));

  // Cadeia de confianca: ancoras embutidas, sem rede.
  item.confianca = await validarCadeia(cert, certificados, dataReferencia);

  item.detached = leitura.detached;
  item.diagnostico = diagnosticar(item);
  return item;
}

/** Caminho CMS: adbe.pkcs7.detached, ETSI.CAdES.detached, ETSI.RFC3161. */
async function lerCms(sig, signedBytes) {
  let signedData;
  try {
    signedData = readSignedData(sig.cms);
  } catch (err) {
    return {
      erro: `contêiner PKCS#7 ilegível: ${err.message}`,
      diagnostico: {
        codigo: 'PKCS7_ILEGIVEL',
        titulo: 'Assinatura ilegível',
        severidade: 'erro',
      },
    };
  }

  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) return { erro: 'SignedData sem SignerInfo' };

  const datas = { signingTimeAtributo: iso(signerInfo.signingTime) };

  const tst = signerInfo.timeStampToken;
  if (tst) {
    datas.carimboDoTempo = {
      genTime: iso(tst.genTime),
      tsa: tst.tsaName,
      tsaSubject: tst.tsaSubject,
      serie: tst.serialHex,
      politica: tst.policy,
      imprintAlgoritmo: tst.imprintAlgorithm,
      imprintHash: tst.imprintHash,
      confereComEstaAssinatura: await verifyTimestampImprint(tst, signerInfo.signature),
    };
  }

  if (sig.sigType === 'DocTimeStamp' && signedData.eContent) {
    datas.carimboDeDocumento = true;
  }

  return {
    formato: 'CMS',
    cert: signerInfo.signerCertificate,
    certificados: signedData.certificates,
    detached: signedData.detached,
    cossignatarios: signedData.signerInfos.length,
    signingTime: signerInfo.signingTime,
    datas,
    cripto: await verifySignerInfo(signerInfo, signedBytes),
    cms: {
      versao: signedData.version,
      algoritmosDigest: signedData.digestAlgorithms.map((a) => a.name ?? a.oid),
      eContentType: CONTENT_TYPES[signedData.eContentType] ?? signedData.eContentType,
      detached: signedData.detached,
      crlsPresentes: signedData.crlsPresent,
      totalCertificados: signedData.certificates.length,
      totalSignerInfos: signedData.signerInfos.length,
      identificacaoSignatario: signerInfo.sidType,
      signedAttrs: signerInfo.signedAttrs.map((a) => a.name ?? a.oid),
      unsignedAttrs: signerInfo.unsignedAttrs.map((a) => a.name ?? a.oid),
    },
  };
}

/**
 * Classifica o quanto a data da assinatura se sustenta.
 *
 * Separa tres coisas que costumam ser confundidas numa so:
 *   1. de onde vem a data - carimbo de uma TSA, atributo assinado, ou apenas o
 *      dicionario do PDF;
 *   2. se esta protegida contra alteracao posterior - o `signingTime` fica
 *      DENTRO dos signedAttrs, entao mudar o valor quebra a assinatura;
 *   3. se ha corroboracao independente - o `notBefore` do certificado e posto
 *      pela AC, nao pelo signatario, e uma assinatura nao pode ser anterior ao
 *      certificado que a produziu.
 *
 * Devolve so dado: o nivel, a fonte e os numeros que sustentam a classificacao.
 * Quem exibe decide como dizer.
 */
function avaliarData(datas, cert) {
  const tst = datas.carimboDoTempo;
  const temAtributoAssinado = !!datas.signingTimeAtributo;

  const base = {
    nivel: null,
    data: null,
    fonte: null,
    protegidaPelaAssinatura: temAtributoAssinado,
    dentroDaVigencia: null,
    minutosAposEmissao: null,
    coincideComDicionario: null,
  };

  if (tst && tst.confereComEstaAssinatura === true) {
    return {
      ...base,
      nivel: 'carimbo',
      data: tst.genTime,
      fonte: 'carimboRfc3161',
      protegidaPelaAssinatura: true,
    };
  }

  if (tst && tst.confereComEstaAssinatura === false) {
    return {
      ...base,
      nivel: 'incoerente',
      data: datas.signingTimeAtributo ?? datas.declaradaNoDicionario,
      fonte: 'carimboDeOutraAssinatura',
    };
  }

  const data = datas.signingTimeAtributo ?? datas.declaradaNoDicionario;
  const referencia = dateOf(data);

  if (cert && referencia && cert.notBefore && cert.notAfter) {
    base.dentroDaVigencia = referencia >= cert.notBefore && referencia <= cert.notAfter;
    const minutos = (referencia - cert.notBefore) / 60000;
    if (minutos >= 0) base.minutosAposEmissao = Math.round(minutos);
  }

  if (datas.signingTimeAtributo && datas.declaradaNoDicionario) {
    const a = dateOf(datas.signingTimeAtributo);
    const b = dateOf(datas.declaradaNoDicionario);
    if (a && b) base.coincideComDicionario = Math.abs(a - b) <= 120000;
  }

  if (base.dentroDaVigencia === false) {
    return { ...base, nivel: 'incoerente', data, fonte: fonteDaData(temAtributoAssinado) };
  }

  return {
    ...base,
    nivel: temAtributoAssinado ? 'coerente' : 'declarada',
    data,
    fonte: fonteDaData(temAtributoAssinado),
  };
}

function fonteDaData(temAtributoAssinado) {
  return temAtributoAssinado ? 'atributoAssinado' : 'dicionarioDoPdf';
}

/**
 * Classifica o modo de falha.
 *
 * A distincao que importa: assinatura que confere com a chave do certificado
 * mas cujo hash do conteudo nao bate NAO e assinatura falsa. E assinatura
 * autentica referente a outro arquivo. O titulo diz isso; os numeros que
 * sustentam estao em `cobertura`.
 */
function diagnosticar(item) {
  const c = item.cripto ?? {};

  if (c.assinaturaOk === true && c.integro !== false) {
    return { codigo: 'VALIDA', titulo: 'Assinatura válida' };
  }

  if (c.assinaturaOk === true && c.integro === false) {
    return {
      codigo: 'CONTEUDO_DIVERGENTE',
      titulo: 'Autêntica, de outro arquivo',
      severidade: 'erro',
    };
  }

  if (c.assinaturaOk === false) {
    return {
      codigo: 'ASSINATURA_NAO_CONFERE',
      titulo: 'Não confere com a chave',
      severidade: 'erro',
    };
  }

  return {
    codigo: 'INDETERMINADO',
    titulo: 'Não verificada',
    severidade: 'atencao',
  };
}

/**
 * Achados da analise, um por linha, em ordem de gravidade. Sao dado, nao
 * narrativa: cada um e um codigo, um nivel e um rotulo de uma linha.
 */
function montarAlertas(relatorio) {
  const alertas = [];
  const add = (nivel, codigo, resumo) => alertas.push({ nivel, codigo, resumo });

  if (!relatorio.assinado) {
    add('atencao', 'SEM_ASSINATURA', 'Sem assinatura digital');
    return alertas;
  }

  for (const sig of relatorio.assinaturas) {
    const n = sig.indice;

    if (sig.erro) {
      add('erro', 'FALHA_LEITURA', `Assinatura ${n}: falha de leitura`);
      continue;
    }

    if (sig.diagnostico?.severidade) {
      add(sig.diagnostico.severidade, sig.diagnostico.codigo,
        `Assinatura ${n}: ${sig.diagnostico.titulo}`);
    }

    const cob = sig.cobertura ?? {};

    if (cob.level === COBERTURA.COBERTURA_PARCIAL) {
      add('erro', 'COBERTURA_PARCIAL', `Assinatura ${n}: cobertura parcial`);
    }
    if (cob.level === COBERTURA.ALEM_DO_FIM) {
      add('erro', 'ALEM_DO_FIM',
        `Assinatura ${n}: faltam ${cob.bytesFaltando} bytes`);
    }
    if (cob.gapMatchesContents === false) {
      add('atencao', 'CONTENTS_FORA_DE_POSICAO',
        `Assinatura ${n}: /Contents fora de posição`);
    }
    if (cob.inicioNaoZero) {
      add('atencao', 'INICIO_NAO_ZERO', `Assinatura ${n}: não cobre o início`);
    }

    if (sig.registradoNoAcroForm === false) {
      add('atencao', 'ORFA', `Assinatura ${n}: órfã, fora do formulário`);
    }
    if (sig.signatario?.cpfValido === false) {
      add('atencao', 'CPF_INVALIDO', `Assinatura ${n}: CPF com dígito inválido`);
    }
    if (sig.certificado?.vigencia?.vigenteNaAssinatura === false) {
      add('erro', 'FORA_DA_VIGENCIA', `Assinatura ${n}: certificado fora da vigência`);
    }
    if (sig.confianca?.status === 'NAO_CONFIAVEL') {
      add('erro', 'CADEIA_COM_PROBLEMA', `Assinatura ${n}: cadeia com problema`);
    }

    const conf = sig.datas?.confiabilidade;
    if (conf?.nivel === 'incoerente') {
      add('erro', 'DATA_INCOERENTE', `Assinatura ${n}: data inconsistente`);
    } else if (conf?.nivel === 'declarada') {
      add('info', 'DATA_NAO_PROTEGIDA', `Assinatura ${n}: data não protegida`);
    }
  }

  const ultima = relatorio.assinaturas[relatorio.assinaturas.length - 1];
  if (ultima?.cobertura?.bytesAfter > 0) {
    const incremental = ultima.cobertura.level === COBERTURA.REVISAO_ANTERIOR;
    add(incremental ? 'info' : 'atencao', 'BYTES_APOS_ASSINATURA',
      `${ultima.cobertura.bytesAfter} bytes após a última assinatura`);
  }

  const ordem = { erro: 0, atencao: 1, info: 2 };
  return alertas.sort((a, b) => ordem[a.nivel] - ordem[b.nivel]);
}

function serializeValidity(v) {
  if (!v) return null;
  return {
    vigenteNaAssinatura: v.vigenteNaAssinatura,
    referencia: iso(v.referencia),
  };
}

function iso(date) {
  return date instanceof Date && !isNaN(date) ? date.toISOString() : null;
}

function dateOf(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  return isNaN(d) ? null : d;
}

function isPdf(bytes) {
  // A assinatura %PDF- pode aparecer com algum lixo antes; leitores toleram
  // ate 1024 bytes de prefixo.
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, 1024));
  return head.includes('%PDF-');
}
