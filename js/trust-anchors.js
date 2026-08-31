/**
 * trust-anchors.js - Autoridades raiz reconhecidas por esta pagina.
 *
 * GERADO por tools/build-anchors.mjs. Nao edite a mao.
 *
 * Cada ancora e uma impressao digital SHA-256 do certificado raiz, em
 * hexadecimal minusculo. A pagina compara a raiz que veio dentro do PDF com
 * esta lista; so se a impressao casar a raiz e aceitada como ancora.
 *
 * A lista comeca VAZIA de proposito. Uma ancora de confianca precisa ter
 * procedencia declarada: quem usa este validador num contexto que importa tem
 * de poder dizer de onde veio cada raiz. Colocar as raizes extraidas dos
 * proprios documentos de teste seria circular - o documento atestaria a si
 * mesmo.
 *
 * Para popular:
 *
 *   1. Baixe os certificados das ACs Raiz do repositorio oficial do ITI
 *      (gov.br/iti -> Repositorio -> AC Raiz).
 *   2. Coloque os arquivos .crt/.cer/.pem em uma pasta.
 *   3. node tools/build-anchors.mjs <pasta>
 *   4. Confira as impressoes digitais que o script imprime contra as
 *      publicadas pelo ITI antes de commitar o resultado.
 *
 * Sem ancoras, a pagina ainda verifica toda a integridade interna da cadeia
 * (cada certificado assinado pela autoridade seguinte, vigencia, basicConstraints)
 * e informa o status CADEIA_OK_SEM_ANCORA - nunca finge que validou o que nao
 * validou.
 */

/**
 * @typedef {object} Ancora
 * @property {string} nome        nome legivel da autoridade
 * @property {string} sha256      impressao digital do certificado, hex minusculo
 * @property {string} procedencia de onde o certificado foi obtido
 * @property {string} [subject]   DN do titular, para referencia humana
 */

/** @type {Ancora[]} */
export const ANCORAS = [];

/** Indice por impressao digital, montado uma vez. */
const POR_IMPRESSAO = new Map(ANCORAS.map((a) => [a.sha256.toLowerCase(), a]));

/**
 * @param {string} sha256Hex impressao digital do certificado candidato a raiz
 * @returns {Ancora|null}
 */
export function anchorByFingerprint(sha256Hex) {
  return POR_IMPRESSAO.get(String(sha256Hex).toLowerCase()) ?? null;
}
