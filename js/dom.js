/**
 * dom.js - Utilitarios de DOM usados pelo renderizador.
 *
 * Regra que vale para todos: todo texto vindo do PDF entra por textContent.
 * Nada de innerHTML com dado de arquivo - o nome no certificado e o /Reason sao
 * conteudo controlado por quem produziu o documento.
 */

/** Cria elemento com classe e texto, sem interpretar markup. */
export function el(tag, className, texto) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (texto !== undefined && texto !== null) node.textContent = String(texto);
  return node;
}

/**
 * Linha rotulo/valor numa grade de definicoes. Valores vazios sao omitidos -
 * e o que evita renderizar dezenas de campos nulos.
 * @returns {HTMLElement|null} o <dd> criado, para quem quiser ajustar a classe
 */
export function linha(grade, rotulo, valor, extras = {}) {
  if (valor === null || valor === undefined || valor === '') return null;
  const dt = el('dt', null, rotulo);
  const dd = el('dd', extras.className ?? null, valor);
  if (extras.mono) dd.classList.add('mono');
  if (extras.titulo) dd.title = extras.titulo;
  grade.append(dt, dd);
  return dd;
}

export function grade() {
  return el('dl', 'grade');
}

export function bloco(titulo, className = 'bloco') {
  const section = el('section', className);
  if (titulo) section.append(el('h4', 'bloco-titulo', titulo));
  return section;
}

export function recolhivel(rotulo, className = 'recolhivel') {
  const details = el('details', className);
  details.append(el('summary', null, rotulo));
  return details;
}

/** Data e hora no formato brasileiro. */
export function dataHumana(iso) {
  const d = paraData(iso);
  return d ? d.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' }) : null;
}

/** Data e hora sem os segundos, para as linhas compactas. */
export function dataCurta(iso) {
  const d = paraData(iso);
  return d ? d.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : null;
}

/** Só a data, sem hora. */
export function dataSimples(iso) {
  const d = paraData(iso);
  return d ? d.toLocaleDateString('pt-BR') : null;
}


function paraData(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return isNaN(d) ? null : d;
}

export function bytesHumano(n) {
  if (!Number.isFinite(n)) return null;
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

/** Escolhe entre três textos conforme true / false / indefinido. */
export function ternario(valor, seSim, seNao, seNulo) {
  if (valor === true) return seSim;
  if (valor === false) return seNao;
  return seNulo;
}

/** Plural simples: `contar(1, 'página', 'páginas')` -> "1 página". */
export function contar(n, singular, plural) {
  if (!Number.isFinite(n)) return null;
  return `${n.toLocaleString('pt-BR')} ${n === 1 ? singular : plural}`;
}
