/**
 * rotulos.js - Rotulos curtos para os enums do relatorio.
 *
 * O nucleo devolve enum; a traducao para texto vive aqui. Regra: nada aqui
 * passa de uma linha. Interpretacao nao entra nem aqui nem no nucleo.
 */

/** cripto.status -> marca de uma letra. */
export const STATUS_MARCA = {
  VALIDA: '✓',
  INVALIDA: '✗',
  INDETERMINADO: '?',
};

/** cripto.status -> slug de cor usado nas classes CSS. */
export const STATUS_COR = {
  VALIDA: 'ok',
  INVALIDA: 'erro',
  INDETERMINADO: 'atencao',
};

/** cobertura.level */
export const COBERTURA_CURTO = {
  ARQUIVO_INTEIRO: 'arquivo inteiro',
  REVISAO_ANTERIOR: 'revisão vigente',
  COBERTURA_PARCIAL: 'parcial',
  ALEM_DO_FIM: 'aponta para fora',
};

/** confianca.status */
export const CONFIANCA_CURTO = {
  CONFIAVEL: 'raiz reconhecida',
  CADEIA_OK_SEM_ANCORA: 'sem ancoragem',
  NAO_CONFIAVEL: 'com problema',
  INDETERMINADO: 'indeterminada',
};

/** datas.confiabilidade.nivel */
export const DATA_CURTO = {
  carimbo: 'carimbo do tempo',
  coerente: 'pela assinatura',
  declarada: 'só no dicionário',
  incoerente: 'inconsistente',
};
