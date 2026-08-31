/**
 * icpbrasil.js - Extrai a identidade do titular a partir das extensoes
 * ICP-Brasil do certificado (DOC-ICP-04).
 *
 * O otherName e lido pelo OID e os campos de largura fixa sao fatiados pela
 * posicao. Nada aqui usa expressao regular sobre a representacao textual do
 * objeto ASN.1, o que eliminaria o acerto por coincidencia de formato.
 */

import { ICP_OTHER_NAMES } from './oid.js';

/** Classificacao da origem do certificado, pelo emissor. */
export function classifyIssuer(cert) {
  if (!cert) return { origem: null, icpBrasil: false };

  const issuerCN = cert.issuer.attributes.find((a) => a.oid === '2.5.4.3')?.value ?? '';
  const issuerO = cert.issuer.attributes.find((a) => a.oid === '2.5.4.10')?.value ?? '';
  const haystack = `${issuerCN} ${issuerO}`.toLowerCase();

  if (haystack.includes('gov-br') || haystack.includes('governo federal do brasil')) {
    return { origem: 'Gov.br (assinatura eletrônica avançada)', icpBrasil: false };
  }
  if (issuerO.toUpperCase() === 'ICP-BRASIL' || haystack.includes('icp-brasil')) {
    return { origem: `ICP-Brasil (${issuerCN})`, icpBrasil: true };
  }
  return { origem: issuerCN || issuerO || null, icpBrasil: false };
}

/**
 * Le a identidade a partir do Subject Alternative Name.
 * Devolve sempre o mesmo formato, com null nos campos ausentes.
 */
export function extractIdentity(cert) {
  const identity = {
    cpf: null,
    cpfMascarado: null,
    cpfValido: null,
    nascimento: null,
    nomeTitular: null,
    nomeResponsavel: null,
    cnpj: null,
    cnpjValido: null,
    nomeEmpresarial: null,
    email: null,
    emailOrigem: null,
    emailCertificado: null,
    nis: null,
    rg: null,
    tituloEleitor: null,
    tipoCertificado: null,
    camposBrutos: [],
  };
  if (!cert) return identity;

  // O CN de e-CPF ICP-Brasil costuma vir como "NOME:CPF".
  const cn = cert.commonName;
  if (cn) {
    const m = /^(.+?):(\d{11})$/.exec(cn);
    identity.nomeTitular = m ? m[1].trim() : cn;
    if (m && !identity.cpf) {
      identity.cpf = formatCpf(m[2]);
      identity.cpfMascarado = maskCpf(m[2]);
      identity.cpfValido = isValidCpf(m[2]);
    }
  }

  for (const san of cert.subjectAltNames) {
    if (san.type === 'rfc822Name') {
      // O rfc822Name do SAN e o e-mail vinculado a identidade do titular.
      if (!identity.email) {
        identity.email = san.value;
        identity.emailOrigem = 'SAN (rfc822Name)';
      }
      continue;
    }
    if (san.type !== 'otherName') continue;

    const spec = ICP_OTHER_NAMES[san.typeId];

    // Campo preenchido so com zeros e a forma que as ACs usam para dizer "nao
    // informado". Mostrar isso no relatorio e ruido puro.
    if (!/^0*$/.test(String(san.value).trim())) {
      identity.camposBrutos.push({
        oid: san.typeId,
        nome: spec?.name ?? san.typeId,
        valor: san.value,
      });
    }
    if (!spec) continue;

    if (spec.text) {
      if (spec.name === 'nomeResponsavel') identity.nomeResponsavel = san.value.trim();
      if (spec.name === 'nomeEmpresarial') identity.nomeEmpresarial = san.value.trim();
      continue;
    }

    const parsed = sliceLayout(san.value, spec.layout);

    if (parsed.nascimento) identity.nascimento = formatBirthDate(parsed.nascimento);
    if (parsed.cpf) {
      identity.cpf = formatCpf(parsed.cpf);
      identity.cpfMascarado = maskCpf(parsed.cpf);
      identity.cpfValido = isValidCpf(parsed.cpf);
    }
    if (parsed.cnpj) {
      identity.cnpj = formatCnpj(parsed.cnpj);
      identity.cnpjValido = isValidCnpj(parsed.cnpj);
    }
    if (parsed.nis) identity.nis = parsed.nis;
    if (parsed.rg) identity.rg = parsed.rg + (parsed.ufOrgaoRg ? ` (${parsed.ufOrgaoRg})` : '');
    if (parsed.tituloEleitor) identity.tituloEleitor = parsed.tituloEleitor;

    if (spec.tipo && !identity.tipoCertificado) identity.tipoCertificado = spec.tipo;
  }

  // O e-CNPJ traz o nome do responsavel na extensao propria; ele e a pessoa
  // fisica que assinou, e nao a razao social do CN.
  if (identity.nomeResponsavel) identity.nomeTitular = identity.nomeResponsavel;

  // O emailAddress do subject nao vincula identidade: em certificados de
  // plataforma ele costuma ser a caixa de suporte da empresa, e nao o e-mail de
  // quem assinou. Fica em campo separado, rotulado, para nao se passar pelo
  // e-mail do signatario.
  const emailAttr = cert.subject.attributes.find((a) => a.oid === '1.2.840.113549.1.9.1');
  if (emailAttr) identity.emailCertificado = emailAttr.value;

  return identity;
}

/**
 * Fatia campos de largura fixa, tolerando strings mais curtas ou mais longas
 * que o layout. Campos preenchidos so com zeros sao tratados como ausentes,
 * que e como as ACs sinalizam "não informado".
 */
function sliceLayout(value, layout) {
  const digits = String(value).trim();
  const out = {};
  let pos = 0;
  for (const [name, width] of layout) {
    if (pos >= digits.length) break;
    const chunk = digits.slice(pos, pos + width);
    pos += width;
    if (chunk.length === 0) continue;
    if (/^0*$/.test(chunk)) continue; // nao informado
    out[name] = chunk.trim();
  }
  return out;
}

/** DDMMAAAA -> DD/MM/AAAA. Devolve null se a data nao for plausivel. */
function formatBirthDate(raw) {
  if (!/^\d{8}$/.test(raw)) return null;
  const dd = raw.slice(0, 2);
  const mm = raw.slice(2, 4);
  const yyyy = raw.slice(4);
  const day = +dd;
  const month = +mm;
  const year = +yyyy;
  if (month < 1 || month > 12 || day < 1 || day > 31 || year < 1900) return null;
  return `${dd}/${mm}/${yyyy}`;
}

export function formatCpf(raw) {
  const d = onlyDigits(raw);
  if (d.length !== 11) return raw || null;
  return `${d.slice(0, 3)}.${d.slice(3, 6)}.${d.slice(6, 9)}-${d.slice(9)}`;
}

/** Mascara no padrao usado pelo ValidarITI: ***.621.496-** */
export function maskCpf(raw) {
  const d = onlyDigits(raw);
  if (d.length !== 11) return raw || null;
  return `***.${d.slice(3, 6)}.${d.slice(6, 9)}-**`;
}

export function formatCnpj(raw) {
  const d = onlyDigits(raw);
  if (d.length !== 14) return raw || null;
  return `${d.slice(0, 2)}.${d.slice(2, 5)}.${d.slice(5, 8)}/${d.slice(8, 12)}-${d.slice(12)}`;
}

function onlyDigits(s) {
  return String(s ?? '').replace(/\D/g, '');
}

/**
 * Digitos verificadores do CPF. Nao prova identidade - so mostra que o numero
 * gravado no certificado e bem formado.
 */
export function isValidCpf(raw) {
  const d = onlyDigits(raw);
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
  for (const [len, pos] of [[9, 10], [10, 11]]) {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += +d[i] * (pos - i);
    const check = (sum * 10) % 11 % 10;
    if (check !== +d[len]) return false;
  }
  return true;
}

export function isValidCnpj(raw) {
  const d = onlyDigits(raw);
  if (d.length !== 14 || /^(\d)\1{13}$/.test(d)) return false;
  const weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  for (const len of [12, 13]) {
    const w = weights.slice(13 - len);
    let sum = 0;
    for (let i = 0; i < len; i++) sum += +d[i] * w[i];
    const rest = sum % 11;
    const check = rest < 2 ? 0 : 11 - rest;
    if (check !== +d[len]) return false;
  }
  return true;
}
