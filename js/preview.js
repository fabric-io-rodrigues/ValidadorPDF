/**
 * preview.js - Miniatura da primeira pagina, via PDF.js vendorizado.
 *
 * Carregado sob demanda (`import()` dinamico): quem so quer o resultado da
 * validacao nao baixa 1,6 MB de renderizador.
 *
 * POR QUE OS ARQUIVOS VENDORIZADOS TERMINAM EM `.js` E NAO `.mjs`:
 * o Windows registra `.mjs` como `text/plain`, e o `python -m http.server` le
 * essa associacao do registro. O navegador entao recusa o modulo por strict
 * MIME checking ("Expected a JavaScript module script but the server responded
 * with a MIME type of text/plain"), e o preview falha inteiro. Renomear para
 * `.js` resolve em qualquer servidor - Python no Windows, GitHub Pages, IIS -
 * sem depender de configuracao. O conteudo continua sendo modulo ES.
 *
 * POSTURA DE SEGURANCA, para uma ferramenta que analisa documentos suspeitos.
 * O que de fato garante que um PDF hostil nao executa script:
 *   1. `pdf.sandbox` NAO esta vendorizado. Ele e o executor de JavaScript de
 *      documento; sem o arquivo, nao ha o que habilitar.
 *   2. Nunca chamamos `AnnotationLayer.render()`, que e o unico lugar do PDF.js
 *      que aceita `enableScripting`.
 *   3. O PDF.js 5 nao usa `eval` nem `new Function` (por isso a opcao
 *      `isEvalSupported` deixou de existir nessa versao).
 *   4. O PDF nunca vai para um <iframe> nem para o visualizador do navegador.
 * Passar `enableScripting: false` / `isEvalSupported: false` a `getDocument()`
 * seria teatro: nenhuma das duas e opcao de `getDocument` no PDF.js 5 - seriam
 * ignoradas em silencio. Por isso nao estao aqui.
 *
 * Falha no preview nunca derruba o relatorio: a miniatura e enfeite, a
 * validacao e o produto.
 */

const BASE = '../vendor/pdfjs/';

let libPromise = null;
let workerCompartilhado = null;

/** Carrega e configura o PDF.js uma unica vez. */
function obterPdfjs() {
  if (libPromise) return libPromise;

  libPromise = (async () => {
    const mod = await import(`${BASE}pdf.module.js`);
    mod.GlobalWorkerOptions.workerSrc = new URL(
      `${BASE}pdf.worker.module.js`,
      import.meta.url,
    ).href;
    return mod;
  })();

  return libPromise;
}

/**
 * Um worker para todos os arquivos. Sem isso, cada `getDocument()` sobe um
 * Worker novo de 1,2 MB - o PDF.js so reaproveita quando recebe um `worker`
 * ou `workerPort` explicito.
 */
async function obterWorker(lib) {
  if (workerCompartilhado && !workerCompartilhado.destroyed) return workerCompartilhado;
  workerCompartilhado = new lib.PDFWorker({ name: 'preview-validador' });
  return workerCompartilhado;
}

/**
 * Desenha a primeira pagina dentro do container.
 *
 * @param {HTMLElement} container elemento devolvido por renderValidacao()
 * @param {Uint8Array} bytes bytes do PDF; o PDF.js TRANSFERE este buffer, por
 *   isso passamos uma copia e nao reaproveitamos o array depois
 * @param {number} larguraAlvo largura da miniatura em pixels de CSS
 */
export async function renderizarPrimeiraPagina(container, bytes, larguraAlvo = 200) {
  if (!container || !bytes || bytes.length === 0) return false;

  let doc = null;

  try {
    const lib = await obterPdfjs();
    const worker = await obterWorker(lib);

    // `bytes.slice()` porque `getDocument` transfere o buffer para o worker:
    // sem a copia, um retry ou uma segunda leitura receberia array vazio.
    doc = await lib.getDocument({
      data: bytes.slice(),
      worker,
    }).promise;

    const pagina = await doc.getPage(1);

    // Escala para a largura pedida, respeitando a densidade da tela.
    const base = pagina.getViewport({ scale: 1 });
    const dpr = Math.min(globalThis.devicePixelRatio || 1, 2);
    const viewport = pagina.getViewport({ scale: (larguraAlvo / base.width) * dpr });

    const canvas = document.createElement('canvas');
    canvas.className = 'v-preview-canvas';

    // O buffer tem `dpr` vezes mais pixels que o tamanho de exibicao; o CSS
    // (`max-width: 100%; height: auto`) reduz de volta e a miniatura sai
    // nitida. Sem estilo inline, para nao depender de style-src.
    canvas.width = Math.round(viewport.width);
    canvas.height = Math.round(viewport.height);

    // Os mesmos atributos que o PDF.js pediria: sem eles o Chrome avisa
    // "Multiple readback operations using getImageData are faster with
    // willReadFrequently" e o render fica mais lento.
    const ctx = canvas.getContext('2d', { alpha: false, willReadFrequently: true });

    await pagina.render({ canvasContext: ctx, viewport }).promise;

    container.replaceChildren(canvas);
    pagina.cleanup();
    return true;
  } catch (err) {
    // A tela continua discreta, mas o console recebe o motivo. Engolir o erro
    // aqui foi o que deixou a falha de MIME type passar sem sintoma.
    console.warn('[preview] falhou:', err);
    container.replaceChildren(marcadorFalha(err));
    return false;
  } finally {
    // Fora do caminho de sucesso tambem: sem isso, um erro depois do
    // getDocument vaza o documento e mantem o worker ocupado.
    if (doc) {
      try {
        await doc.destroy();
      } catch { /* nada a fazer */ }
    }
  }
}

function marcadorFalha(err) {
  const span = document.createElement('span');
  span.className = 'v-preview-vazio';
  span.textContent = /senha|password/i.test(String(err && err.message))
    ? 'PDF protegido'
    : 'sem preview';
  return span;
}
