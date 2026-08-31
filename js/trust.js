/**
 * trust.js - Validacao da cadeia de certificados, sem rede.
 *
 * Faz duas coisas distintas:
 *
 *   1. INTEGRIDADE - verifica que cada certificado foi assinado pela autoridade
 *      seguinte, que os intermediarios sao ACs e que todos estavam vigentes na
 *      data de referencia. Nao depende de ancora e sempre roda.
 *   2. ANCORAGEM - compara a impressao digital SHA-256 da raiz com a lista de
 *      trust-anchors.js.
 *
 * A ancoragem e por impressao digital, e nao pelo certificado embutido, porque
 * a raiz que vem dentro do PDF foi posta la por quem produziu o arquivo:
 * confiar nela seria circular. A ancora tem de vir de fora.
 *
 * NAO consulta CRL nem OCSP: revogacao exige rede. Certificado revogado dentro
 * da vigencia aparece aqui como cadeia valida.
 */

import { verifyWithCertificate, fingerprint } from './verify.js';
import { ANCORAS, anchorByFingerprint } from './trust-anchors.js';

export const CONFIANCA = {
  CONFIAVEL: 'CONFIAVEL',
  CADEIA_OK_SEM_ANCORA: 'CADEIA_OK_SEM_ANCORA',
  NAO_CONFIAVEL: 'NAO_CONFIAVEL',
  INDETERMINADO: 'INDETERMINADO',
};

/**
 * @param {import('./x509.js').Certificate} signerCert
 * @param {import('./x509.js').Certificate[]} embedded certificados do PKCS#7
 * @param {Date|null} referencia data para aferir vigencia
 */
export async function validarCadeia(signerCert, embedded, referencia) {
  if (!signerCert) {
    return {
      status: CONFIANCA.INDETERMINADO,
      caminho: [],
      ancora: null,
      ancorasCarregadas: ANCORAS.length,
      revogacaoVerificada: false,
    };
  }

  const caminho = construirCaminho(signerCert, embedded);
  const elos = [];
  let integra = true;

  // Verifica cada elo: o filho tem de ser assinado pela chave do pai.
  for (let i = 0; i < caminho.length; i++) {
    const atual = caminho[i];
    const pai = caminho[i + 1] ?? (atual.selfIssued ? atual : null);

    const elo = {
      commonName: atual.commonName,
      serieHex: `0x${atual.serialNumberHex}`,
      emissor: atual.issuerHumanFriendly,
      autoridadeCertificadora: atual.isCA,
      autoAssinado: atual.selfIssued,
      impressaoSha256: await fingerprint(atual.der),
      vigente: vigenteEm(atual, referencia),
      assinadoPeloProximo: null,
      observacoes: [],
    };

    if (elo.vigente === false) {
      integra = false;
      elo.observacoes.push('fora da vigência na data de referência');
    }

    if (i > 0 && !atual.isCA) {
      integra = false;
      elo.observacoes.push('usado como autoridade certificadora sem basicConstraints CA:TRUE');
    }

    if (pai) {
      const alg = atual.outerSignatureAlgorithm;
      const digest = alg.digest ?? null;
      const veredito = await verifyWithCertificate(
        pai, atual.signatureValue, atual.tbs.bytes, alg.name, digest,
      );
      elo.assinadoPeloProximo = veredito.ok;
      if (veredito.ok === false) {
        integra = false;
        elo.observacoes.push('a assinatura da autoridade emissora não confere');
      } else if (veredito.ok === null) {
        elo.observacoes.push(...veredito.observacoes);
      }
    } else {
      elo.observacoes.push('emissor não está embutido no arquivo');
    }

    elos.push(elo);
  }

  const topo = caminho[caminho.length - 1];
  const raizAutoAssinada = topo?.selfIssued ?? false;
  const impressaoTopo = elos[elos.length - 1]?.impressaoSha256 ?? null;
  const ancora = impressaoTopo ? anchorByFingerprint(impressaoTopo) : null;

  const resultado = {
    caminho: elos,
    cadeiaIntegra: integra,
    raizAutoAssinada,
    impressaoRaiz: impressaoTopo,
    ancora,
    ancorasCarregadas: ANCORAS.length,
    revogacaoVerificada: false,
    completa: raizAutoAssinada,
  };

  if (!integra) {
    return { ...resultado, status: CONFIANCA.NAO_CONFIAVEL };
  }

  if (ancora) {
    return { ...resultado, status: CONFIANCA.CONFIAVEL };
  }

  return { ...resultado, status: CONFIANCA.CADEIA_OK_SEM_ANCORA };
}

/**
 * Ordena os certificados do signatario para a raiz.
 *
 * Casa emissor por DN e, quando disponivel, confirma pelo par
 * authorityKeyIdentifier / subjectKeyIdentifier - dois certificados podem
 * compartilhar o DN de emissor apos renovacao da AC, e o identificador de chave
 * e o que desempata.
 */
function construirCaminho(signerCert, embedded) {
  const caminho = [signerCert];
  const usados = new Set([signerCert.der]);

  let atual = signerCert;
  while (caminho.length < 12) {
    if (atual.selfIssued) break;

    const pai = embedded.find((c) => {
      if (usados.has(c.der)) return false;
      if (!mesmoDn(c.subject.der, atual.issuer.der)) return false;
      const aki = atual.authorityKeyId;
      const ski = c.subjectKeyId;
      if (aki && ski) return aki === ski;
      return true;
    });

    if (!pai) break;
    caminho.push(pai);
    usados.add(pai.der);
    atual = pai;
  }

  return caminho;
}

function mesmoDn(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function vigenteEm(cert, referencia) {
  if (!referencia || !cert.notBefore || !cert.notAfter) return null;
  return referencia >= cert.notBefore && referencia <= cert.notAfter;
}

