/**
 * validador.js - Controlador da pagina de uso.
 *
 * Um relatorio por vez: cada arquivo aberto substitui o anterior. A area de
 * arrastar desaparece depois do primeiro arquivo e o arrastar-e-soltar passa a
 * valer na janela inteira.
 */

import { renderValidacao } from './render-simples.js';
import { el, bloco } from './dom.js';

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const saida = document.getElementById('saida');
const progresso = document.getElementById('progresso');
const progressoTexto = document.getElementById('progressoTexto');
const acoes = document.getElementById('acoes');
const cortina = document.getElementById('cortina');
const btnOutro = document.getElementById('btnOutro');
const btnDump = document.getElementById('btnDump');
const btnImprimir = document.getElementById('btnImprimir');

/** Relatorios do lote atual, para o dump. */
let relatorios = [];

let worker = null;
let proximoId = 1;
let ocupado = false;

const pendentes = new Map();

// ------------------------------------------------------------------- worker

function obterWorker() {
  if (worker !== null) return worker;
  try {
    worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });

    worker.onmessage = (evento) => {
      const { id, tipo, etapa, relatorio, mensagem } = evento.data;
      const tarefa = pendentes.get(id);
      if (!tarefa) return;

      if (tipo === 'progresso') {
        tarefa.onProgresso(etapa);
      } else if (tipo === 'ok') {
        pendentes.delete(id);
        tarefa.resolve(relatorio);
      } else {
        pendentes.delete(id);
        tarefa.reject(new Error(mensagem));
      }
    };

    worker.onerror = (e) => {
      for (const [id, tarefa] of pendentes) {
        pendentes.delete(id);
        tarefa.reject(new Error(e.message || 'falha no worker de análise'));
      }
    };
  } catch {
    worker = false;
  }
  return worker;
}

async function analisar(bytes, nome, onProgresso) {
  const w = obterWorker();

  if (w === false) {
    const { analisarPdf } = await import('./analyze.js');
    return analisarPdf(bytes, nome, onProgresso);
  }

  const id = proximoId++;
  return new Promise((resolve, reject) => {
    pendentes.set(id, { resolve, reject, onProgresso });
    const buffer = bytes.buffer;
    w.postMessage({ id, nome, bytes: buffer }, [buffer]);
  });
}

// ------------------------------------------------------------------- eventos

dropZone.addEventListener('click', abrirSeletor);
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    abrirSeletor();
  }
});
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('arrastando');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('arrastando'));

fileInput.addEventListener('change', (e) => {
  const arquivos = e.target.files;
  fileInput.value = '';
  processar(arquivos);
});

btnOutro.addEventListener('click', abrirSeletor);
btnImprimir.addEventListener('click', () => window.print());

btnDump.addEventListener('click', async () => {
  const { baixarDump } = await import('./dump.js');
  baixarDump(relatorios);
});

function abrirSeletor() {
  if (!ocupado) fileInput.click();
}

let profundidadeArraste = 0;

window.addEventListener('dragenter', (e) => {
  if (!temArquivo(e)) return;
  e.preventDefault();
  profundidadeArraste++;
  if (!ocupado) cortina.hidden = false;
});

window.addEventListener('dragover', (e) => {
  if (temArquivo(e)) e.preventDefault();
});

window.addEventListener('dragleave', (e) => {
  if (!temArquivo(e)) return;
  profundidadeArraste = Math.max(0, profundidadeArraste - 1);
  if (profundidadeArraste === 0) cortina.hidden = true;
});

window.addEventListener('drop', (e) => {
  if (!temArquivo(e)) return;
  e.preventDefault();
  profundidadeArraste = 0;
  cortina.hidden = true;
  dropZone.classList.remove('arrastando');
  processar(e.dataTransfer.files);
});

function temArquivo(evento) {
  const tipos = evento.dataTransfer?.types;
  return !!tipos && Array.prototype.includes.call(tipos, 'Files');
}

// ----------------------------------------------------------------- pipeline

async function processar(fileList) {
  if (ocupado) return;

  const arquivos = [...fileList].filter(
    (f) => f.type === 'application/pdf' || f.name.toLowerCase().endsWith('.pdf'),
  );

  if (arquivos.length === 0) {
    mostrarProgresso('Selecione um arquivo PDF.', false);
    return;
  }

  ocupado = true;
  relatorios = [];
  saida.replaceChildren();
  acoes.hidden = true;
  dropZone.setAttribute('aria-busy', 'true');

  for (let i = 0; i < arquivos.length; i++) {
    const arquivo = arquivos[i];
    const rotulo = arquivos.length > 1
      ? `${arquivo.name} (${i + 1} de ${arquivos.length})`
      : arquivo.name;

    mostrarProgresso(`Analisando ${rotulo}`, true);

    const container = document.createElement('div');
    container.className = 'v-container';
    saida.append(container);

    try {
      const original = new Uint8Array(await arquivo.arrayBuffer());

      // O worker recebe o buffer por transferencia (zero-copia), o que o
      // esvazia aqui. O preview precisa dos bytes depois disso, entao guarda
      // uma copia ANTES de enviar.
      const paraPreview = original.slice();

      const relatorio = await analisar(original, arquivo.name, (etapa) => {
        mostrarProgresso(`${rotulo} — ${etapa}`, true);
      });

      relatorios.push(relatorio);
      const alvoPreview = renderValidacao(relatorio, container);

      if (alvoPreview) desenharPreview(alvoPreview, paraPreview);
    } catch (err) {
      relatorios.push({
        arquivo: { nome: arquivo.name },
        erro: err && err.message ? err.message : String(err),
      });
      renderErro(container, arquivo.name, err);
    }
  }

  ocupado = false;
  dropZone.removeAttribute('aria-busy');
  dropZone.hidden = true;
  acoes.hidden = false;
  esconderProgresso();

  const primeiro = saida.firstElementChild;
  if (primeiro) {
    primeiro.scrollIntoView({
      behavior: prefereMovimentoReduzido() ? 'auto' : 'smooth',
      block: 'start',
    });
  }
}

/**
 * O preview roda depois do relatorio, sem travar nada: importa o PDF.js sob
 * demanda e falha em silencio. A validacao e o produto; a miniatura e enfeite.
 */
function desenharPreview(alvo, bytes) {
  import('./preview.js')
    .then(({ renderizarPrimeiraPagina }) => renderizarPrimeiraPagina(alvo, bytes))
    .catch((err) => {
      // Engolir este erro em silencio foi o que deixou uma falha de MIME type
      // no modulo do PDF.js passar sem sintoma. A tela segue discreta, o
      // console recebe o motivo.
      console.warn('[preview] nao foi possivel carregar o renderizador:', err);
    });
}

function prefereMovimentoReduzido() {
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

/**
 * Falha na leitura do arquivo. Usa a mesma aparencia do bloco de assinaturas,
 * que e o unico lugar da pagina que informa situacao.
 */
function renderErro(container, nome, err) {
  const artigo = el('article', 'v-relatorio');
  const secao = bloco('Não foi possível analisar', 'v-bloco');

  const identidade = el('div', 'v-assinatura-identidade');
  identidade.append(el('p', 'v-assinatura-nome', nome));
  identidade.append(el('p', 'v-assinatura-meta', err && err.message ? err.message : String(err)));

  const cabeca = el('div', 'v-assinatura-cabeca');
  cabeca.append(el('span', 'v-marca v-marca-erro', '✗'));
  cabeca.append(identidade);

  const item = el('li', 'v-assinatura v-erro');
  item.append(cabeca);

  const lista = el('ul', 'v-assinaturas');
  lista.append(item);

  secao.append(lista);
  artigo.append(secao);
  container.append(artigo);
}

function mostrarProgresso(texto, emAndamento) {
  progressoTexto.textContent = texto;
  progresso.hidden = false;
  progresso.classList.toggle('ocupado', !!emAndamento);
}

function esconderProgresso() {
  progresso.hidden = true;
  progressoTexto.textContent = '';
  progresso.classList.remove('ocupado');
}

// -------------------------------------------------------------- PWA

/*
 * Registro do service worker. Caminho relativo porque no GitHub Pages o site
 * fica em usuario.github.io/repositorio/ - um caminho absoluto registraria no
 * escopo errado e nao pegaria nada.
 *
 * Falha aqui e irrelevante para o funcionamento: sem service worker a pagina
 * continua validando normalmente, so nao abre offline nem oferece instalacao.
 */
if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register(new URL('../sw.js', import.meta.url), { scope: './' })
      .catch((err) => console.warn('[pwa] service worker nao registrado:', err));
  });
}
