/** oid.js - Tabela de OIDs relevantes para CMS, X.509 e ICP-Brasil. */

/** Atributos de Distinguished Name. `short` segue a convencao RFC 4514. */
export const DN_ATTRS = {
  '2.5.4.3': { short: 'CN', label: 'Common Name' },
  '2.5.4.4': { short: 'SN', label: 'Surname' },
  '2.5.4.5': { short: 'serialNumber', label: 'Serial Number' },
  '2.5.4.6': { short: 'C', label: 'Country' },
  '2.5.4.7': { short: 'L', label: 'Locality' },
  '2.5.4.8': { short: 'ST', label: 'State/Province' },
  '2.5.4.9': { short: 'STREET', label: 'Street Address' },
  '2.5.4.10': { short: 'O', label: 'Organization' },
  '2.5.4.11': { short: 'OU', label: 'Organizational Unit' },
  '2.5.4.12': { short: 'title', label: 'Title' },
  '2.5.4.42': { short: 'GN', label: 'Given Name' },
  '2.5.4.46': { short: 'dnQualifier', label: 'DN Qualifier' },
  '2.5.4.65': { short: 'pseudonym', label: 'Pseudonym' },
  '1.2.840.113549.1.9.1': { short: 'E', label: 'Email Address' },
  '0.9.2342.19200300.100.1.25': { short: 'DC', label: 'Domain Component' },
  '0.9.2342.19200300.100.1.1': { short: 'UID', label: 'User ID' },
};

/** Extensoes X.509. */
export const EXTENSIONS = {
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.17': 'Subject Alternative Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.37': 'Extended Key Usage',
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
};

/** Atributos CMS (signedAttrs / unsignedAttrs). */
export const CMS_ATTRS = {
  '1.2.840.113549.1.9.3': 'contentType',
  '1.2.840.113549.1.9.4': 'messageDigest',
  '1.2.840.113549.1.9.5': 'signingTime',
  '1.2.840.113549.1.9.6': 'counterSignature',
  '1.2.840.113549.1.9.16.2.12': 'signingCertificate',
  '1.2.840.113549.1.9.16.2.47': 'signingCertificateV2',
  '1.2.840.113549.1.9.16.2.14': 'signatureTimeStampToken',
  '1.2.840.113549.1.9.52': 'cmsAlgorithmProtection',
  '1.2.840.113549.1.9.16.2.20': 'contentTimeStamp',
  '1.2.840.113549.1.9.15': 'smimeCapabilities',
  '1.2.840.113549.1.9.16.2.7': 'contentIdentifier',
  '1.2.840.113583.1.1.8': 'adbeRevocationInfoArchival',
};

export const CONTENT_TYPES = {
  '1.2.840.113549.1.7.1': 'data',
  '1.2.840.113549.1.7.2': 'signedData',
  '1.2.840.113549.1.9.16.1.4': 'tstInfo',
};

/**
 * Algoritmos de digest -> nome WebCrypto.
 * A tabela e a fronteira do que a pagina consegue verificar: um algoritmo
 * ausente aqui produz status INDETERMINADO, nunca um falso "invalido".
 */
export const DIGEST_ALGS = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
  '2.16.840.1.101.3.4.2.4': 'SHA-224',
};

/**
 * Algoritmos de assinatura -> {família, digest}.
 * `rsaEncryption` (1.2.840.113549.1.1.1) aparece como signatureAlgorithm em
 * muitos SignerInfo: nesse caso o digest vem do campo digestAlgorithm.
 */
export const SIG_ALGS = {
  '1.2.840.113549.1.1.1': { family: 'RSA', digest: null },
  '1.2.840.113549.1.1.5': { family: 'RSA', digest: 'SHA-1' },
  '1.2.840.113549.1.1.11': { family: 'RSA', digest: 'SHA-256' },
  '1.2.840.113549.1.1.12': { family: 'RSA', digest: 'SHA-384' },
  '1.2.840.113549.1.1.13': { family: 'RSA', digest: 'SHA-512' },
  '1.2.840.113549.1.1.14': { family: 'RSA', digest: 'SHA-224' },
  '1.2.840.113549.1.1.10': { family: 'RSA-PSS', digest: null },
  '1.2.840.10045.4.1': { family: 'ECDSA', digest: 'SHA-1' },
  '1.2.840.10045.4.3.2': { family: 'ECDSA', digest: 'SHA-256' },
  '1.2.840.10045.4.3.3': { family: 'ECDSA', digest: 'SHA-384' },
  '1.2.840.10045.4.3.4': { family: 'ECDSA', digest: 'SHA-512' },
  '1.2.840.10045.2.1': { family: 'ECDSA', digest: null },
};

/**
 * otherName da ICP-Brasil dentro do Subject Alternative Name (DOC-ICP-04).
 * Cada campo e uma string de digitos de largura fixa; `layout` descreve os
 * pedacos na ordem em que aparecem.
 *
 * As larguras seguem o DOC-ICP-04, mas ACs divergem no preenchimento final
 * (vimos valores de 45 e 55 digitos para o mesmo OID), por isso o leitor em
 * icpbrasil.js consome o layout de forma tolerante em vez de exigir o total.
 */
export const ICP_OTHER_NAMES = {
  '2.16.76.1.3.1': {
    name: 'dadosPessoaFisica',
    tipo: 'e-CPF',
    layout: [
      ['nascimento', 8],
      ['cpf', 11],
      ['nis', 11],
      ['rg', 15],
      ['ufOrgaoRg', 6],
    ],
  },
  '2.16.76.1.3.5': {
    name: 'dadosEleitorais',
    layout: [
      ['tituloEleitor', 12],
      ['zonaEleitoral', 3],
      ['secao', 4],
      ['municipioUf', 22],
    ],
  },
  '2.16.76.1.3.6': { name: 'cei', layout: [['cei', 12]] },
  '2.16.76.1.3.2': { name: 'nomeResponsavel', text: true },
  '2.16.76.1.3.3': { name: 'cnpj', layout: [['cnpj', 14]] },
  '2.16.76.1.3.4': {
    name: 'dadosResponsavel',
    tipo: 'e-CNPJ',
    layout: [
      ['nascimento', 8],
      ['cpf', 11],
      ['nis', 11],
      ['rg', 15],
      ['ufOrgaoRg', 6],
    ],
  },
  '2.16.76.1.3.7': { name: 'ceiPessoaJuridica', layout: [['cei', 12]] },
  '2.16.76.1.3.8': { name: 'nomeEmpresarial', text: true },
  '2.16.76.1.3.9': { name: 'registroOab', text: true },
};

/** Politicas de certificado que identificam a origem (uso informativo). */
export const CERT_POLICIES = {
  '2.16.76.1.2.1': 'ICP-Brasil A1',
  '2.16.76.1.2.2': 'ICP-Brasil A2',
  '2.16.76.1.2.3': 'ICP-Brasil A3',
  '2.16.76.1.2.4': 'ICP-Brasil A4',
  '2.16.76.1.2.101': 'ICP-Brasil S1',
  '2.16.76.1.2.201': 'ICP-Brasil T3',
};
