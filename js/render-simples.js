/**
 * render-simples.js - Renderizador da pagina.
 *
 * Regra que define este arquivo: NENHUM texto explicativo. O nucleo devolve
 * enum e numero; aqui eles viram rotulo de uma linha. Nada de paragrafo.
 *
 * Os achados da analise (`relatorio.alertas`) tambem NAO entram: um achado
 * exibido fora de contexto pode ser lido como defeito do documento quando nao
 * e. O que sinaliza problema e o selo da assinatura mais o titulo do
 * diagnostico. Os alertas seguem no relatorio e no dump.
 *
 * O preview da primeira pagina nao e montado aqui: este modulo produz um
 * container vazio e quem chama o preenche.
 */

import {
  el, linha, grade, bloco, recolhivel,
  dataHumana, dataCurta, dataSimples, bytesHumano, ternario, contar,
} from './dom.js';
import {
  STATUS_MARCA, STATUS_COR,
  COBERTURA_CURTO, CONFIANCA_CURTO, DATA_CURTO,
} from './rotulos.js';

/**
 * @param {object} rel relatorio de analisarPdf()
 * @param {HTMLElement} container
 * @returns {HTMLElement|null} o container do preview, para quem for preenche-lo
 */
export function renderValidacao(rel, container) {
  container.replaceChildren();

  const artigo = el('article', 'v-relatorio');

  if (rel.erro) {
    artigo.append(secaoFalha(rel.erro));
    container.append(artigo);
    return null;
  }

  const { secao, preview } = secaoDocumento(rel);
  artigo.append(secao);

  // Nao existe mais faixa de veredito. O bloco de assinaturas e o unico lugar
  // que responde "vale ou nao vale", e por isso ele aparece SEMPRE - inclusive
  // quando nao ha assinatura nenhuma, caso em que traz essa informacao.
  artigo.append(secaoAssinaturas(rel));

  container.append(artigo);
  return preview;
}


// ----------------------------------------------------------------- documento

function secaoDocumento(rel) {
  const secao = bloco(null, 'v-bloco v-documento');
  const a = rel.arquivo;

  const preview = el('div', 'v-preview');
  preview.append(el('span', 'v-preview-vazio', 'PDF'));
  secao.append(preview);

  const dados = el('div', 'v-documento-dados');
  dados.append(el('h2', 'v-nome-arquivo', a.nome));

  // Linha de fatos curtos, separados por ponto medio.
  const fatos = [
    bytesHumano(a.tamanho),
    contar(a.paginas, 'página', 'páginas'),
    a.formatoPagina,
    a.versaoPdf ? `PDF ${a.versaoPdf}` : null,
    contar(a.revisoes, 'revisão', 'revisões'),
    a.cifrado ? 'cifrado' : null,
  ].filter(Boolean);

  const linhaFatos = el('p', 'v-fatos');
  for (const f of fatos) linhaFatos.append(el('span', null, f));
  dados.append(linhaFatos);

  const g = grade();
  linha(g, 'Título', a.titulo);
  linha(g, 'Autor', a.autor);
  linha(g, 'Produtor', a.produtor);
  linha(g, 'Criado em', dataHumana(a.criadoEm));
  linha(g, 'Modificado em', dataHumana(a.modificadoEm));
  linha(g, 'SHA-256', a.sha256, { mono: true });
  dados.append(g);

  /*
   * Metadado nao padrao do /Info, recolhido. Fica fora da grade porque e
   * imprevisivel em tamanho: num dos arquivos de teste sao oito chaves de
   * rotulo de sensibilidade com GUID no nome, que empurrariam o bloco de
   * assinaturas para fora da tela no celular. Recolhido, avisa que existe sem
   * custar espaco.
   */
  const extra = Object.entries(a.infoExtra ?? {});
  if (extra.length) dados.append(blocoInfoExtra(extra));

  secao.append(dados);
  return { secao, preview };
}

function blocoInfoExtra(entradas) {
  const det = recolhivel(`Outros metadados (${entradas.length})`, 'v-detalhes');
  const lista = el('ul', 'v-extra');

  for (const [chave, valor] of entradas) {
    const item = el('li', 'v-extra-item');
    item.append(el('span', 'v-extra-chave', chave));
    item.append(el('span', 'v-extra-valor', valor));
    lista.append(item);
  }

  det.append(lista);
  return det;
}

// --------------------------------------------------------------- assinaturas

function secaoAssinaturas(rel) {
  const total = rel.assinaturas.length;

  const secao = bloco(
    total === 0 ? 'Assinaturas' : (total === 1 ? 'Assinatura' : `Assinaturas (${total})`),
    'v-bloco',
  );

  const lista = el('ul', 'v-assinaturas');

  if (total === 0) {
    lista.append(itemEstado('atencao', '!', 'Sem assinatura digital'));
  } else {
    for (const sig of rel.assinaturas) lista.append(itemAssinatura(sig));
  }

  secao.append(lista);
  return secao;
}

/** Bloco para arquivo que nem chegou a ser analisado. */
function secaoFalha(mensagem) {
  const secao = bloco('Falha na leitura', 'v-bloco');
  const lista = el('ul', 'v-assinaturas');
  lista.append(itemEstado('erro', '✗', mensagem));
  secao.append(lista);
  return secao;
}

/**
 * Item com a mesma aparencia de uma assinatura, mas so com um estado. Mantem
 * uma linguagem visual unica agora que a faixa de veredito nao existe mais.
 */
function itemEstado(cor, marca, texto) {
  const li = el('li', `v-assinatura v-${cor}`);
  const cabeca = el('div', 'v-assinatura-cabeca');
  cabeca.append(el('span', `v-marca v-marca-${cor}`, marca));

  const identidade = el('div', 'v-assinatura-identidade');
  identidade.append(el('p', 'v-assinatura-nome', texto));
  cabeca.append(identidade);

  li.append(cabeca);
  return li;
}

function itemAssinatura(sig) {
  const status = sig.erro ? 'INVALIDA' : (sig.cripto?.status ?? 'INDETERMINADO');
  const cor = STATUS_COR[status] ?? 'atencao';

  const li = el('li', `v-assinatura v-${cor}`);

  const cabeca = el('div', 'v-assinatura-cabeca');
  cabeca.append(el('span', `v-marca v-marca-${cor}`, STATUS_MARCA[status] ?? '?'));

  const identidade = el('div', 'v-assinatura-identidade');

  // Nome com o documento entre parenteses. O CPF e o documento da pessoa que
  // assinou; em certificado e-CNPJ o CNPJ da empresa fica nos detalhes.
  const nome = el('p', 'v-assinatura-nome');
  nome.append(el('span', 'v-assinatura-titular',
    sig.signatario?.nomeExibicao || sig.nomeDeclarado || sig.campo || 'Sem identificação'));

  const documento = sig.signatario?.cpf ?? sig.signatario?.cnpj;
  if (documento) nome.append(el('span', 'v-assinatura-doc', `(${documento})`));
  identidade.append(nome);

  // A data e o dado mais consultado do relatorio, por isso sai destacada em
  // vez de diluida no meio da linha de metadados.
  const linhaMeta = el('p', 'v-assinatura-meta');
  const quando = dataCurta(sig.datas?.confiabilidade?.data);
  if (quando) linhaMeta.append(el('strong', 'v-assinatura-data', quando));

  for (const m of [sig.signatario?.tipoCertificado, origemCurta(sig.signatario?.origem)]) {
    if (m) linhaMeta.append(el('span', null, m));
  }
  identidade.append(linhaMeta);

  // Quando algo esta errado, o titulo do diagnostico entra aqui - curto, sem
  // o paragrafo que o acompanha no nucleo.
  if (sig.diagnostico?.severidade) {
    identidade.append(el('p', `v-assinatura-problema v-texto-${cor}`, sig.diagnostico.titulo));
  } else if (sig.erro) {
    identidade.append(el('p', 'v-assinatura-problema v-texto-erro', sig.erro));
  }

  cabeca.append(identidade);
  li.append(cabeca);

  if (!sig.erro) li.append(detalhesAssinatura(sig));
  return li;
}

/** "ICP-Brasil (AC Certisign RFB G5)" -> "ICP-Brasil". */
function origemCurta(origem) {
  if (!origem) return null;
  const m = /^([^(]+)/.exec(origem);
  return m ? m[1].trim() : origem;
}

function detalhesAssinatura(sig) {
  const det = recolhivel('Detalhes', 'v-detalhes');
  const s = sig.signatario ?? {};

  const g = grade();
  linha(g, 'CPF', s.cpfValido === false ? `${s.cpf} · dígito inválido` : s.cpf);
  linha(g, 'Nascimento', s.nascimento);
  linha(g, 'E-mail', s.email);
  linha(g, 'CNPJ', s.cnpj);
  linha(g, 'Empresa', s.nomeEmpresarial);
  linha(g, 'RG', s.rg);
  linha(g, 'NIS/PIS', s.nis);
  linha(g, 'Título de eleitor', s.tituloEleitor);
  linha(g, 'Certificado', s.tipoCertificado);
  linha(g, 'Emitido por', s.origem);

  const conf = sig.datas?.confiabilidade;
  linha(g, 'Data da assinatura', dataHumana(conf?.data));
  linha(g, 'Garantia da data', conf ? DATA_CURTO[conf.nivel] ?? conf.nivel : null);

  const tst = sig.datas?.carimboDoTempo;
  if (tst) {
    linha(g, 'Carimbo do tempo', dataHumana(tst.genTime));
    linha(g, 'Autoridade', tst.tsa);
  }

  const cert = sig.certificado;
  if (cert) {
    linha(g, 'Nº de série', cert.serieHex, { mono: true });
    linha(g, 'Emissor', apenasCN(cert.issuer));
    linha(g, 'Válido de', dataSimples(cert.notBefore));
    linha(g, 'Válido até', dataSimples(cert.notAfter));
    if (cert.vigencia) {
      linha(g, 'Vigente ao assinar', ternario(
        cert.vigencia.vigenteNaAssinatura, 'sim', 'não', null,
      ));
    }
  }

  const c = sig.cripto ?? {};
  linha(g, 'Conteúdo intacto', ternario(c.integro, 'sim', 'não', null));
  linha(g, 'Confere com a chave', ternario(c.assinaturaOk, 'sim', 'não', null));
  linha(g, 'Algoritmo', c.assinaturaAlgoritmo);
  linha(g, 'Abrangência', COBERTURA_CURTO[sig.cobertura?.level] ?? null);
  linha(g, 'No formulário', ternario(sig.registradoNoAcroForm, 'sim', 'não', null));

  det.append(g);

  // Cadeia de apoio: so vale mostrar quando ha mais de um elo. Com um elo, o
  // unico item e o certificado do proprio signatario, que ja esta acima.
  const caminho = sig.confianca?.caminho ?? [];
  if (caminho.length > 1) {
    det.append(el('h5', 'v-sub-titulo', 'Cadeia'));
    det.append(listaCadeia(sig.confianca));
  } else {
    const gc = grade();
    linha(gc, 'Cadeia', 'ausente');
    det.append(gc);
  }

  return det;
}

function listaCadeia(confianca) {
  const wrap = el('div', 'v-cadeia-wrap');

  const ol = el('ol', 'v-cadeia');
  for (let i = 0; i < confianca.caminho.length; i++) {
    const elo = confianca.caminho[i];
    const item = el('li', 'v-cadeia-elo');

    const marca = elo.assinadoPeloProximo === true ? 'ok'
      : elo.assinadoPeloProximo === false ? 'erro' : 'neutro';
    item.append(el('span', `v-marca-mini v-marca-${marca}`,
      marca === 'ok' ? '✓' : marca === 'erro' ? '✗' : '·'));

    item.append(el('span', 'v-cadeia-nome', elo.commonName ?? '(sem nome)'));

    const papel = i === 0 ? 'signatário' : (elo.autoAssinado ? 'raiz' : 'intermediária');
    item.append(el('span', 'v-cadeia-papel', papel));

    ol.append(item);
  }
  wrap.append(ol);

  const g = grade();
  linha(g, 'Situação', CONFIANCA_CURTO[confianca.status] ?? confianca.status);
  wrap.append(g);

  return wrap;
}

/** Extrai só o Common Name de um DN completo. */
function apenasCN(dn) {
  if (!dn) return null;
  const m = /Common Name:\s*([^;,]+)/.exec(dn);
  return m ? m[1].trim() : dn;
}


