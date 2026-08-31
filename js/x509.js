/**
 * x509.js - Leitura de certificados X.509 (RFC 5280) sobre o parser DER.
 *
 * Expoe os bytes exatos do SubjectPublicKeyInfo, que e o formato "spki" que a
 * WebCrypto aceita em importKey - por isso o parser nao copia buffers.
 */

import {
  TAG, CONTEXT, decodeOID, decodeString, decodeTime, serialToHex, parse, toHex,
  bitStringBytes,
} from './der.js';
import { DN_ATTRS, EXTENSIONS, ICP_OTHER_NAMES, SIG_ALGS, CERT_POLICIES } from './oid.js';

/**
 * Certificate  ::=  SEQUENCE  {
 *   tbsCertificate       TBSCertificate,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING  }
 *
 * TBSCertificate ::= SEQUENCE {
 *   version         [0] EXPLICIT Version DEFAULT v1,
 *   serialNumber        CertificateSerialNumber,
 *   signature           AlgorithmIdentifier,
 *   issuer              Name,
 *   validity            Validity,
 *   subject             Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo,
 *   ... extensions  [3] EXPLICIT Extensions OPTIONAL }
 */
export class Certificate {
  constructor(node) {
    this.node = node;
    this.der = node.bytes;

    const tbs = node.at(0);
    this.tbs = tbs;

    let i = 0;
    const children = tbs.children;

    // version e [0] EXPLICIT e opcional (ausente = v1).
    if (children[i] && children[i].isContext(0)) {
      this.version = Number(children[i].at(0).content[0]) + 1;
      i++;
    } else {
      this.version = 1;
    }

    this.serialNumberHex = serialToHex(children[i++]);
    this.signatureAlgorithm = readAlgorithmIdentifier(children[i++]);
    this.issuer = readName(children[i++]);

    const validity = children[i++];
    this.notBefore = decodeTime(validity.at(0));
    this.notAfter = decodeTime(validity.at(1));

    this.subject = readName(children[i++]);

    // SubjectPublicKeyInfo: guardamos o TLV inteiro para a WebCrypto.
    const spki = children[i++];
    this.spki = spki.bytes;
    this.publicKeyAlgorithm = readAlgorithmIdentifier(spki.at(0));

    this.extensions = [];
    const extsWrapper = children.find((c) => c.cls === CONTEXT && c.tagNo === 3);
    if (extsWrapper && extsWrapper.at(0)) {
      for (const ext of extsWrapper.at(0).children) {
        this.extensions.push(readExtension(ext));
      }
    }

    // AlgorithmIdentifier e assinatura do proprio certificado (nivel externo,
    // fora do tbsCertificate). Sao o que a validacao de cadeia verifica: a
    // assinatura da AC emissora sobre os bytes de `tbs`.
    this.outerSignatureAlgorithm = readAlgorithmIdentifier(node.at(1));
    this.signatureValue = bitStringBytes(node.at(2));
  }

  static fromDER(bytes) {
    return new Certificate(parse(bytes));
  }

  extension(oid) {
    return this.extensions.find((e) => e.oid === oid);
  }

  /** Primeiro valor de um atributo do subject (ex.: '2.5.4.3' = CN). */
  subjectAttr(oid) {
    return this.subject.attributes.find((a) => a.oid === oid)?.value ?? null;
  }

  get commonName() {
    return this.subjectAttr('2.5.4.3');
  }

  /**
   * Subject no formato "human_friendly" do asn1crypto - o mesmo que a maioria
   * das ferramentas de linha de comando imprime, o que permite conferir lado a
   * lado.
   */
  get subjectHumanFriendly() {
    return humanFriendly(this.subject);
  }

  get issuerHumanFriendly() {
    return humanFriendly(this.issuer);
  }

  /** Subject Alternative Name decodificado, ou lista vazia. */
  get subjectAltNames() {
    const ext = this.extension('2.5.29.17');
    return ext ? ext.value : [];
  }

  get policies() {
    const ext = this.extension('2.5.29.32');
    return ext ? ext.value : [];
  }

  get isCA() {
    const ext = this.extension('2.5.29.19');
    return ext ? !!ext.value.ca : false;
  }

  get keyUsage() {
    const ext = this.extension('2.5.29.15');
    return ext ? ext.value : [];
  }

  /** Subject Key Identifier em hexadecimal, ou null. */
  get subjectKeyId() {
    return this.extension('2.5.29.14')?.value ?? null;
  }

  /** keyIdentifier do Authority Key Identifier em hexadecimal, ou null. */
  get authorityKeyId() {
    return this.extension('2.5.29.35')?.value?.keyIdentifier ?? null;
  }

  /** true se o certificado e assinado por ele mesmo (candidato a raiz). */
  get selfIssued() {
    return this.subject.der.length === this.issuer.der.length
      && this.subject.der.every((b, i) => b === this.issuer.der[i]);
  }
}

function readAlgorithmIdentifier(node) {
  const oid = decodeOID(node.at(0));
  const params = node.at(1);
  return {
    oid,
    name: SIG_ALGS[oid]?.family ?? null,
    digest: SIG_ALGS[oid]?.digest ?? null,
    params: params && !params.is(TAG.NULL) ? params : null,
  };
}

/**
 * Name ::= RDNSequence; cada RelativeDistinguishedName e um SET de
 * AttributeTypeAndValue. Guardamos os RDNs agrupados, e nao so a lista plana,
 * porque um RDN multivalorado (varios OU no mesmo SET) precisa ser distinguido
 * de varios RDNs de um atributo cada.
 */
function readName(node) {
  const rdns = [];
  const attributes = [];

  for (const rdn of node.children) {
    const group = [];
    for (const atv of rdn.children) {
      const oid = decodeOID(atv.at(0));
      const attr = {
        oid,
        short: DN_ATTRS[oid]?.short ?? oid,
        label: DN_ATTRS[oid]?.label ?? oid,
        value: decodeString(atv.at(1)),
      };
      group.push(attr);
      attributes.push(attr);
    }
    rdns.push(group);
  }
  return { rdns, attributes, der: node.bytes };
}

/**
 * Reproduz `Name.human_friendly` do asn1crypto, para que o DN possa ser
 * conferido lado a lado com outras ferramentas.
 *
 * O algoritmo tem tres peculiaridades que precisam ser copiadas ao pe da letra,
 * senao as strings divergem:
 *   1. atributos de mesmo tipo sao agrupados em todo o DN, nao dentro do RDN;
 *   2. os valores agrupados saem em ordem inversa a do DER;
 *   3. o separador entre campos e "; " se algum campo contiver virgula, e ", "
 *      caso contrario.
 * Para exibir na interface, prefira `subject.attributes`, que e estruturado.
 */
function humanFriendly(name) {
  const grouped = new Map();
  let lastLabel = null;

  for (const attr of name.attributes) {
    lastLabel = attr.label;
    if (grouped.has(attr.label)) grouped.get(attr.label).push(attr.value);
    else grouped.set(attr.label, [attr.value]);
  }

  let labels = [...grouped.keys()];
  if (lastLabel === 'Country') labels.reverse();

  const parts = labels.map(
    (label) => `${label}: ${grouped.get(label).slice().reverse().join(', ')}`,
  );

  const separator = parts.some((p) => p.includes(',')) ? '; ' : ', ';
  return parts.reverse().join(separator);
}

function readExtension(node) {
  const children = node.children;
  const oid = decodeOID(children[0]);
  let critical = false;
  let idx = 1;
  if (children[idx] && children[idx].is(TAG.BOOLEAN)) {
    critical = children[idx].content[0] !== 0;
    idx++;
  }
  const octet = children[idx];
  const ext = {
    oid,
    name: EXTENSIONS[oid] ?? oid,
    critical,
    raw: octet ? octet.content : new Uint8Array(0),
    value: null,
  };

  try {
    ext.value = decodeExtensionValue(oid, ext.raw);
  } catch {
    ext.value = null; // extensao malformada nao derruba a leitura do certificado
  }
  return ext;
}

function decodeExtensionValue(oid, raw) {
  if (raw.length === 0) return null;
  switch (oid) {
    case '2.5.29.17':
      return readGeneralNames(parse(raw));
    case '2.5.29.19': {
      const seq = parse(raw);
      const first = seq.at(0);
      return {
        ca: first && first.is(TAG.BOOLEAN) ? first.content[0] !== 0 : false,
      };
    }
    case '2.5.29.15':
      return readKeyUsage(parse(raw));
    case '2.5.29.32':
      return parse(raw).children.map((pi) => {
        const policyOid = decodeOID(pi.at(0));
        return { oid: policyOid, name: CERT_POLICIES[policyOid] ?? policyOid };
      });
    case '2.5.29.14':
      return toHex(parse(raw).content);
    case '2.5.29.35': {
      // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, ... }
      const seq = parse(raw);
      const keyId = seq.children.find((c) => c.cls === CONTEXT && c.tagNo === 0);
      return { keyIdentifier: keyId ? toHex(keyId.content) : null };
    }
    case '2.5.29.37':
      return parse(raw).children.map((c) => decodeOID(c));
    default:
      return null;
  }
}

const KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

function readKeyUsage(node) {
  const content = node.content;
  if (content.length < 2) return [];
  const unused = content[0];
  const bytes = content.subarray(1);
  const totalBits = bytes.length * 8 - unused;
  const out = [];
  for (let bit = 0; bit < totalBits && bit < KEY_USAGE_BITS.length; bit++) {
    if (bytes[bit >> 3] & (0x80 >> (bit & 7))) out.push(KEY_USAGE_BITS[bit]);
  }
  return out;
}

/**
 * GeneralNames ::= SEQUENCE OF GeneralName
 *   otherName [0], rfc822Name [1], dNSName [2], uniformResourceIdentifier [6]...
 *
 * Aqui a estrutura e lida, e nao a representacao textual do objeto: o
 * otherName e um SEQUENCE
 * {type-id OID, value [0] EXPLICIT ANY} e o valor da ICP-Brasil vem como
 * OCTET STRING, PrintableString ou UTF8String, dependendo da AC.
 */
function readGeneralNames(node) {
  const names = [];
  for (const gn of node.children) {
    if (gn.tagNo === 0 && gn.cls === CONTEXT) {
      const typeId = decodeOID(gn.at(0));
      const wrapper = gn.at(1);
      const inner = wrapper && wrapper.constructed ? wrapper.at(0) : wrapper;
      names.push({
        type: 'otherName',
        typeId,
        typeName: ICP_OTHER_NAMES[typeId]?.name ?? typeId,
        value: inner ? decodeString(inner) : '',
      });
    } else if (gn.tagNo === 1 && gn.cls === CONTEXT) {
      names.push({ type: 'rfc822Name', value: decodeString(gn) });
    } else if (gn.tagNo === 2 && gn.cls === CONTEXT) {
      names.push({ type: 'dNSName', value: decodeString(gn) });
    } else if (gn.tagNo === 6 && gn.cls === CONTEXT) {
      names.push({ type: 'uri', value: decodeString(gn) });
    } else if (gn.tagNo === 4 && gn.cls === CONTEXT) {
      names.push({ type: 'directoryName', value: humanFriendly(readName(gn.at(0))) });
    } else {
      names.push({ type: `[${gn.tagNo}]`, value: toHex(gn.content) });
    }
  }
  return names;
}
