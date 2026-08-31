/**
 * worker.js - Executa a analise fora da thread principal.
 *
 * O core (analyze.js e abaixo) nao toca no DOM, entao roda aqui sem adaptacao.
 * Mesmo com a analise ja otimizada para dezenas de milissegundos, um PDF muito
 * grande ou muito estranho nao pode congelar a interface: a pagina precisa
 * continuar respondendo e mostrando em que etapa esta.
 */

import { analisarPdf } from './analyze.js';

self.onmessage = async (evento) => {
  const { id, nome, bytes } = evento.data;

  const onProgresso = (etapa) => {
    self.postMessage({ id, tipo: 'progresso', etapa });
  };

  try {
    const relatorio = await analisarPdf(new Uint8Array(bytes), nome, onProgresso);
    self.postMessage({ id, tipo: 'ok', relatorio });
  } catch (err) {
    self.postMessage({
      id,
      tipo: 'erro',
      mensagem: err && err.message ? err.message : String(err),
    });
  }
};
