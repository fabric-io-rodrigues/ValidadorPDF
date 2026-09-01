/**
 * sw.js - Service worker do ValidadorPDF.
 *
 * Deliberadamente burro, e por um motivo de seguranca, nao de simplicidade.
 *
 * A pagina declara `connect-src 'none'` na CSP, e o README trata isso como
 * garantia de que o arquivo nao sai da maquina. Um service worker NAO herda a
 * CSP do documento - ele tem a propria, vinda dos cabecalhos HTTP da resposta
 * do proprio script, que aqui nao existem. Ou seja: este arquivo e o unico
 * lugar do projeto onde um `fetch()` para qualquer host funcionaria.
 *
 * Por isso ele obedece a tres regras:
 *
 *   1. So responde a requisicoes de MESMA ORIGEM. Qualquer outra e ignorada
 *      (segue para a rede pelo caminho normal do navegador, sem passar por
 *      aqui).
 *   2. So busca na rede URLs que estao nas listas abaixo, e apenas por
 *      GET. Nao existe cache dinamico de "o que aparecer".
 *   3. Nunca ve os bytes do PDF. O arquivo e lido por `arrayBuffer()` na
 *      pagina e nunca vira uma requisicao HTTP - nao ha o que interceptar.
 *
 * Se alguem editar este arquivo para adicionar um `fetch` a outro host, estara
 * furando a garantia da pagina inteira, e nao apenas mexendo em cache.
 */

/*
 * INCREMENTE A CADA PUBLICACAO que mude qualquer arquivo da lista abaixo.
 *
 * A estrategia e cache-first: um app ja instalado serve do cache e NAO vai a
 * rede conferir se mudou. Sem o incremento, quem instalou continua com a versao
 * velha indefinidamente - e o erro classico de PWA. Nao basta mudar o conteudo
 * do arquivo, tem de mudar esta string.
 */
const VERSAO = 'validadorpdf-v4';
const CACHE_APP = `${VERSAO}-app`;
const CACHE_PREVIEW = `${VERSAO}-preview`;

/**
 * O essencial: entra no cache na instalacao. Sao ~120 kB, entao a instalacao
 * fica rapida e o app abre offline mesmo sem nunca ter usado o preview.
 */
const APP = [
  './',
  './index.html',
  './css/validador.css',
  './js/validador.js',
  './js/render-simples.js',
  './js/dom.js',
  './js/rotulos.js',
  './js/worker.js',
  './js/analyze.js',
  './js/pdfdoc.js',
  './js/pdfsig.js',
  './js/pdfmeta.js',
  './js/objstm.js',
  './js/cms.js',
  './js/der.js',
  './js/x509.js',
  './js/oid.js',
  './js/icpbrasil.js',
  './js/verify.js',
  './js/trust.js',
  './js/trust-anchors.js',
  './js/preview.js',
  './js/dump.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/icon-180.png',
];

/**
 * O PDF.js sao 1,6 MB dos ~1,7 MB do app. Fica fora da instalacao e entra no
 * cache no primeiro uso do preview, para nao pesar a primeira visita nem a
 * instalacao no celular.
 */
const SOB_DEMANDA = [
  './vendor/pdfjs/pdf.module.js',
  './vendor/pdfjs/pdf.worker.module.js',
];

const permitidos = new Set(
  [...APP, ...SOB_DEMANDA].map((u) => new URL(u, self.registration.scope).href),
);

// -------------------------------------------------------------------- ciclo

self.addEventListener('install', (evento) => {
  evento.waitUntil((async () => {
    const cache = await caches.open(CACHE_APP);
    // addAll aborta tudo se um item falhar; individual e mais tolerante a um
    // arquivo renomeado do que deixar a instalacao inteira sem cache.
    await Promise.all(APP.map(async (url) => {
      try {
        await cache.add(new Request(url, { cache: 'reload' }));
      } catch (err) {
        console.warn('[sw] nao cacheou', url, err);
      }
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (evento) => {
  evento.waitUntil((async () => {
    const nomes = await caches.keys();
    await Promise.all(
      nomes.filter((n) => !n.startsWith(VERSAO)).map((n) => caches.delete(n)),
    );
    await self.clients.claim();
  })());
});

// -------------------------------------------------------------------- fetch

self.addEventListener('fetch', (evento) => {
  const { request } = evento;

  // Regra 2: so GET.
  if (request.method !== 'GET') return;

  // Regra 1: so mesma origem. Sem isto, o worker se tornaria um proxy.
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Navegacao: cache-first no shell, para abrir offline.
  if (request.mode === 'navigate') {
    evento.respondWith(responderNavegacao(request));
    return;
  }

  // Regra 2 de novo: fora das listas, nao intercepta.
  if (!permitidos.has(url.href)) return;

  const cacheAlvo = SOB_DEMANDA.some((u) => url.href.endsWith(u.replace('./', '')))
    ? CACHE_PREVIEW
    : CACHE_APP;

  evento.respondWith(cachePrimeiro(request, cacheAlvo));
});

async function responderNavegacao(request) {
  const cache = await caches.open(CACHE_APP);
  const guardado = await cache.match('./index.html');
  if (guardado) return guardado;

  try {
    return await fetch(request);
  } catch {
    return new Response(
      '<!doctype html><meta charset="utf-8"><p>Sem conexão e sem cópia local.',
      { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
    );
  }
}

async function cachePrimeiro(request, nomeCache) {
  const cache = await caches.open(nomeCache);
  const guardado = await cache.match(request);
  if (guardado) return guardado;

  const resposta = await fetch(request);
  // Só guarda resposta boa: um 404 em cache é pior que nenhum cache.
  if (resposta.ok && resposta.type === 'basic') {
    cache.put(request, resposta.clone());
  }
  return resposta;
}
