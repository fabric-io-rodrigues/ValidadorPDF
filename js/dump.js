/**
 * dump.js - Baixa tudo que foi extraido do PDF, em JSON.
 *
 * A pagina mostra o que responde "vale ou nao vale". O dump traz o resto: o
 * /ByteRange como esta no arquivo, os atributos CMS assinados, todas as
 * extensoes do certificado, a cadeia inteira, as chaves nao padrao do /Info.
 *
 * E dado, nao parecer: o nucleo nao produz frase nenhuma, entao nao ha o que
 * filtrar aqui - o relatorio inteiro pode ir cru.
 *
 * O arquivo e gerado por Blob local. Nenhum byte sai do navegador.
 */

/**
 * @param {object[]} relatorios saida de analisarPdf(), um por arquivo aberto
 */
export function baixarDump(relatorios) {
  if (!relatorios || relatorios.length === 0) return;

  const payload = {
    ferramenta: 'ValidadorPDF',
    geradoEm: new Date().toISOString(),
    arquivos: relatorios,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json;charset=utf-8',
  });

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = nomeDoArquivo(relatorios);
  a.click();
  URL.revokeObjectURL(url);
}

function nomeDoArquivo(relatorios) {
  if (relatorios.length === 1 && relatorios[0].arquivo?.nome) {
    return `${relatorios[0].arquivo.nome.replace(/\.pdf$/i, '')}.dump.json`;
  }
  return `validadorpdf-${relatorios.length}-arquivos.dump.json`;
}
