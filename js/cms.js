/**
 * cms.js - Leitura de CMS / PKCS#7 SignedData (RFC 5652) e de tokens de
 * carimbo do tempo RFC 3161.
 *
 * O detalhe critico esta em `signedAttrsForVerification`: no SignerInfo o campo
 * signedAttrs e codificado como [0] IMPLICIT, mas a assinatura e calculada
 * sobre a mesma estrutura re-codificada como SET explicito (tag 0x31). Errar
 * esse byte faz toda assinatura parecer invalida.
 */

import {
  TAG, CONTEXT, parse, decodeOID, decodeInteger,
  decodeTime, serialToHex, toHex,
} from './der.js';
import { Certificate } from './x509.js';
import { CMS_ATTRS, CONTENT_TYPES, DIGEST_ALGS, SIG_ALGS } from './oid.js';

export class CmsError extends Error {}

/** ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY } */
export function readContentInfo(bytes) {
  const root = parse(bytes);
  if (!root.is(TAG.SEQUENCE)) throw new CmsError('ContentInfo não é um SEQUENCE');
  const contentType = decodeOID(root.at(0));
  const wrapper = root.context(0);
  return {
    contentType,
    contentTypeName: CONTENT_TYPES[contentType] ?? contentType,
    content: wrapper ? wrapper.at(0) : null,
    node: root,
  };
}

/**
 * SignedData ::= SEQUENCE {
 *   version INTEGER, digestAlgorithms SET, encapContentInfo,
 *   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL,
 *   signerInfos SET OF SignerInfo }
 */
export class SignedData {
  constructor(node) {
    this.node = node;
    const children = node.children;

    let i = 0;
    this.version = Number(decodeInteger(children[i++]));

    this.digestAlgorithms = children[i++].children.map((a) => {
      const oid = decodeOID(a.at(0));
      return { oid, name: DIGEST_ALGS[oid] ?? oid };
    });

    // EncapsulatedContentInfo: em assinatura detached o eContent esta ausente.
    const encap = children[i++];
    this.eContentType = decodeOID(encap.at(0));
    const eWrapper = encap.context(0);
    this.eContent = eWrapper && eWrapper.at(0) ? eWrapper.at(0).content : null;
    this.detached = this.eContent === null;

    this.certificates = [];
    this.crlsPresent = false;

    for (; i < children.length; i++) {
      const c = children[i];
      if (c.cls === CONTEXT && c.tagNo === 0) {
        for (const certNode of c.children) {
          // O CertificateSet aceita outros formatos ([1] attribute cert etc.);
          // so um SEQUENCE universal e um Certificate X.509.
          if (!certNode.is(TAG.SEQUENCE)) continue;
          try {
            this.certificates.push(new Certificate(certNode));
          } catch {
            /* certificado ilegivel nao invalida os demais */
          }
        }
      } else if (c.cls === CONTEXT && c.tagNo === 1) {
        this.crlsPresent = true;
      } else if (c.is(TAG.SET)) {
        this.signerInfos = c.children.map((si) => new SignerInfo(si, this));
      }
    }

    if (!this.signerInfos) this.signerInfos = [];
  }
}

export class SignerInfo {
  constructor(node, signedData) {
    this.node = node;
    this.signedData = signedData;
    const children = node.children;

    let i = 0;
    this.version = Number(decodeInteger(children[i++]));

    // SignerIdentifier: IssuerAndSerialNumber (SEQUENCE) ou [0] subjectKeyIdentifier.
    const sid = children[i++];
    if (sid.is(TAG.SEQUENCE)) {
      this.sidType = 'issuerAndSerialNumber';
      this.sidIssuerDer = sid.at(0).bytes;
      this.sidSerialHex = serialToHex(sid.at(1));
    } else {
      this.sidType = 'subjectKeyIdentifier';
      this.sidKeyId = toHex(sid.content);
      this.sidSerialHex = null;
    }

    const digestAlgOid = decodeOID(children[i++].at(0));
    this.digestAlgorithm = { oid: digestAlgOid, name: DIGEST_ALGS[digestAlgOid] ?? null };

    this.signedAttrsNode = null;
    this.unsignedAttrsNode = null;

    if (children[i] && children[i].cls === CONTEXT && children[i].tagNo === 0) {
      this.signedAttrsNode = children[i++];
    }

    const sigAlgOid = decodeOID(children[i++].at(0));
    this.signatureAlgorithm = {
      oid: sigAlgOid,
      family: SIG_ALGS[sigAlgOid]?.family ?? null,
      digest: SIG_ALGS[sigAlgOid]?.digest ?? null,
    };

    this.signature = children[i++].content;

    if (children[i] && children[i].cls === CONTEXT && children[i].tagNo === 1) {
      this.unsignedAttrsNode = children[i++];
    }

    this.signedAttrs = this.signedAttrsNode ? readAttributes(this.signedAttrsNode) : [];
    this.unsignedAttrs = this.unsignedAttrsNode ? readAttributes(this.unsignedAttrsNode) : [];
  }

  attr(name) {
    return this.signedAttrs.find((a) => a.name === name);
  }

  unsignedAttr(name) {
    return this.unsignedAttrs.find((a) => a.name === name);
  }

  /** messageDigest declarado nos signedAttrs (OCTET STRING). */
  get messageDigest() {
    const a = this.attr('messageDigest');
    return a && a.values[0] ? a.values[0].content : null;
  }

  /** signingTime auto-declarado pelo signatario (nao confiavel por si so). */
  get signingTime() {
    const a = this.attr('signingTime');
    return a && a.values[0] ? decodeTime(a.values[0]) : null;
  }

  get declaredContentType() {
    const a = this.attr('contentType');
    if (!a || !a.values[0]) return null;
    const oid = decodeOID(a.values[0]);
    return CONTENT_TYPES[oid] ?? oid;
  }

  /**
   * Bytes sobre os quais a assinatura foi calculada.
   * Com signedAttrs presente: a SET re-codificada como tag explicito 0x31.
   * Sem signedAttrs: o proprio conteudo assinado.
   */
  signedAttrsForVerification() {
    const node = this.signedAttrsNode;
    if (!node) return null;

    if (!node.indefinite) {
      // Caminho comum: basta trocar o byte de identificador [0] -> SET.
      const copy = new Uint8Array(node.bytes);
      copy[0] = 0x31;
      return copy;
    }
    // BER de comprimento indefinido: re-emite com comprimento definido.
    return encodeSet(node.content);
  }

  /** Certificado do signatario, casado por issuer+serial (nao por posicao). */
  get signerCertificate() {
    const certs = this.signedData.certificates;
    if (certs.length === 0) return null;

    if (this.sidType === 'issuerAndSerialNumber') {
      const wanted = this.sidIssuerDer;
      const match = certs.find(
        (c) => c.serialNumberHex === this.sidSerialHex && bytesEqual(c.issuer.der, wanted),
      );
      if (match) return match;
      // Alguns emissores codificam o DN de forma diferente do certificado;
      // o serial sozinho ja e suficientemente discriminante como fallback.
      const bySerial = certs.find((c) => c.serialNumberHex === this.sidSerialHex);
      if (bySerial) return bySerial;
    } else if (this.sidKeyId) {
      const match = certs.find((c) => c.extension('2.5.29.14')?.value === this.sidKeyId);
      if (match) return match;
    }
    return null;
  }

  /** Token RFC 3161 do unsignedAttr signatureTimeStampToken, se houver. */
  get timeStampToken() {
    const a = this.unsignedAttr('signatureTimeStampToken');
    if (!a || !a.values[0]) return null;
    try {
      return readTimeStampToken(a.values[0].bytes);
    } catch {
      return null;
    }
  }
}

/** Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY } */
function readAttributes(setNode) {
  return setNode.children.map((attr) => {
    const oid = decodeOID(attr.at(0));
    const valuesNode = attr.at(1);
    return {
      oid,
      name: CMS_ATTRS[oid] ?? oid,
      values: valuesNode ? valuesNode.children : [],
    };
  });
}

/**
 * TimeStampToken e um ContentInfo/SignedData cujo eContent e um TSTInfo DER.
 * O genTime dele e a hora atestada por terceiro - diferente do signingTime,
 * que o proprio signatario declara.
 */
export function readTimeStampToken(bytes) {
  const ci = readContentInfo(bytes);
  if (ci.contentTypeName !== 'signedData') throw new CmsError('token não é signedData');
  const sd = new SignedData(ci.content);
  if (!sd.eContent) throw new CmsError('TSTInfo ausente no token');

  const info = parse(sd.eContent);
  const children = info.children;
  const policy = decodeOID(children[1]);
  const messageImprint = children[2];
  const imprintAlg = decodeOID(messageImprint.at(0).at(0));

  // genTime vem depois de serialNumber; localizamos pelo tipo para tolerar
  // variacoes de campos opcionais entre TSAs.
  const genTimeNode = children.find((c) => c.is(TAG.GENERALIZED_TIME));

  const tsaCert = sd.signerInfos[0]?.signerCertificate ?? sd.certificates[0] ?? null;

  return {
    genTime: genTimeNode ? decodeTime(genTimeNode) : null,
    policy,
    serialHex: serialToHex(children[3]),
    imprintAlgorithm: DIGEST_ALGS[imprintAlg] ?? imprintAlg,
    imprintHash: toHex(messageImprint.at(1).content),
    tsaName: tsaCert ? tsaCert.commonName : null,
    tsaSubject: tsaCert ? tsaCert.subjectHumanFriendly : null,
    signedData: sd,
  };
}

/** Envelope SET (0x31) com comprimento definido a partir do conteudo. */
function encodeSet(content) {
  const len = content.length;
  let header;
  if (len < 0x80) {
    header = [0x31, len];
  } else {
    const lenBytes = [];
    let n = len;
    while (n > 0) {
      lenBytes.unshift(n & 0xff);
      n = Math.floor(n / 256);
    }
    header = [0x31, 0x80 | lenBytes.length, ...lenBytes];
  }
  const out = new Uint8Array(header.length + len);
  out.set(header, 0);
  out.set(content, header.length);
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Le um contêiner PKCS#7 e devolve o SignedData. */
export function readSignedData(bytes) {
  const ci = readContentInfo(bytes);
  if (ci.contentTypeName !== 'signedData') {
    throw new CmsError(`contentType inesperado: ${ci.contentTypeName}`);
  }
  if (!ci.content) throw new CmsError('SignedData ausente');
  return new SignedData(ci.content);
}
