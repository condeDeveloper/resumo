using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Conde.Resumo.Testes;

/// <summary>
/// O ataque de extensão de comprimento, feito de verdade — e o HMAC resistindo.
/// </summary>
/// <remarks>
/// <para>
/// Estes testes não conferem uma implementação: eles <b>quebram</b> um esquema
/// de autenticação e mostram o conserto funcionando. É a demonstração mais útil
/// do projeto, porque a construção que ela quebra parece obviamente segura.
/// </para>
/// </remarks>
public class ExtensaoTest
{
    /// <summary>
    /// Um servidor que assina do jeito ingênuo. Ele é a vítima.
    /// </summary>
    /// <remarks>
    /// O segredo nunca sai daqui — e o ataque funciona assim mesmo, que é o
    /// ponto inteiro.
    /// </remarks>
    private sealed class ServidorIngenuo(byte[] segredo)
    {
        public byte[] Assinar(byte[] mensagem) =>
            Extensao.AssinaturaIngenua(segredo, mensagem);

        public bool Aceita(byte[] mensagem, byte[] assinatura) =>
            Hmac.Iguais(Assinar(mensagem), assinatura);
    }

    private sealed class ServidorComHmac(byte[] segredo)
    {
        public byte[] Assinar(byte[] mensagem) => Hmac.Sha256(segredo, mensagem);

        public bool Aceita(byte[] mensagem, byte[] assinatura) =>
            Hmac.Iguais(Assinar(mensagem), assinatura);
    }

    [Fact(DisplayName = "o ataque funciona: assino uma mensagem sem saber o segredo")]
    public void OAtaqueFunciona()
    {
        var segredo = Encoding.UTF8.GetBytes("um segredo de 24 bytes!!");

        var servidor = new ServidorIngenuo(segredo);

        // O que o atacante vê: uma mensagem pública e a assinatura dela.
        var mensagem = Encoding.UTF8.GetBytes("usuario=joao&admin=nao");
        var assinatura = servidor.Assinar(mensagem);

        // O que ele quer acrescentar.
        var acrescimo = Encoding.UTF8.GetBytes("&admin=sim");

        // Ele sabe o tamanho do segredo -- ou o descobre em 64 tentativas.
        var forjado = Extensao.Estender(assinatura, segredo.Length, mensagem, acrescimo);

        // E o servidor aceita. O atacante nunca soube o segredo.
        Assert.True(
            servidor.Aceita(forjado.NovaMensagem, forjado.NovaAssinatura),
            "o servidor devia ter aceitado a mensagem forjada");

        // A mensagem forjada termina com o acréscimo, que é o que o atacante
        // queria -- e a maioria dos formatos ignora os bytes estranhos do meio
        // ou toma o último valor de cada chave.
        Assert.EndsWith("&admin=sim", Encoding.UTF8.GetString(forjado.NovaMensagem));
        Assert.StartsWith("usuario=joao&admin=nao", Encoding.UTF8.GetString(forjado.NovaMensagem));
    }

    [Fact(DisplayName = "o atacante nem precisa saber o tamanho do segredo")]
    public void NemPrecisaSaberOTamanho()
    {
        // Na prática ele testa de 1 a 64 e vê qual o servidor aceita. São 64
        // tentativas -- nada, num sistema que não limite as tentativas. E mesmo
        // com limite, 64 é pouco.
        var sorteio = new Random(20260929);

        for (var i = 0; i < 40; i++)
        {
            var tamanho = sorteio.Next(1, 60);
            var segredo = new byte[tamanho];

            sorteio.NextBytes(segredo);

            var servidor = new ServidorIngenuo(segredo);

            var mensagem = Encoding.UTF8.GetBytes($"conta=123&valor={i}");
            var assinatura = servidor.Assinar(mensagem);

            var descoberto = Extensao.DescobrirTamanhoDoSegredo(
                assinatura,
                mensagem,
                Encoding.UTF8.GetBytes("&valor=999999"),
                servidor.Aceita);

            Assert.Equal(tamanho, descoberto);
        }
    }

    [Fact(DisplayName = "o HMAC não cede")]
    public void OHmacNaoCede()
    {
        // O mesmo ataque, contra o servidor que assina direito. Ele não anda:
        // o resumo publicado não é o estado interno de nada que dê para
        // continuar, porque há uma segunda passada depois dele.
        var segredo = Encoding.UTF8.GetBytes("um segredo de 24 bytes!!");

        var servidor = new ServidorComHmac(segredo);

        var mensagem = Encoding.UTF8.GetBytes("usuario=joao&admin=nao");
        var assinatura = servidor.Assinar(mensagem);

        var acrescimo = Encoding.UTF8.GetBytes("&admin=sim");

        // Tenta com TODOS os tamanhos de segredo possíveis.
        for (var tamanho = 1; tamanho <= 128; tamanho++)
        {
            var tentativa = Extensao.Estender(assinatura, tamanho, mensagem, acrescimo);

            Assert.False(
                servidor.Aceita(tentativa.NovaMensagem, tentativa.NovaAssinatura),
                $"o HMAC cedeu com tamanho de segredo {tamanho} -- isto seria grave");
        }

        var descoberto = Extensao.DescobrirTamanhoDoSegredo(
            assinatura, mensagem, acrescimo, servidor.Aceita, ate: 128);

        Assert.Null(descoberto);
    }

    [Fact(DisplayName = "o SHA-512/256 também não cede, e por outro motivo")]
    public void OSha512Barra256NaoCede()
    {
        // Ele é imune por construção: o resumo publicado tem 256 bits e o estado
        // interno tem 512. Metade do estado fica de fora, e sem ela não há de
        // onde continuar.
        //
        // É a mesma ideia do SHA-3, que resolveu o problema de vez trocando a
        // construção inteira -- e é por isso que o SHA-3 não precisa de HMAC
        // para autenticar, basta pôr a chave na frente.
        var segredo = Encoding.UTF8.GetBytes("um segredo de 24 bytes!!");
        var mensagem = Encoding.UTF8.GetBytes("usuario=joao&admin=nao");

        byte[] Assinar(byte[] m) => Sha512.De512Barra256([.. segredo, .. m]);

        var assinatura = Assinar(mensagem);

        // A assinatura tem 32 bytes, do mesmo tamanho de um SHA-256 -- então o
        // ataque RODA. Ele só não funciona: os 32 bytes não são o estado
        // interno, são metade dele, e a outra metade são 2^256 possibilidades.
        Assert.Equal(32, assinatura.Length);

        var acrescimo = Encoding.UTF8.GetBytes("&admin=sim");

        for (var tamanho = 1; tamanho <= 128; tamanho++)
        {
            var tentativa = Extensao.Estender(assinatura, tamanho, mensagem, acrescimo);

            Assert.False(
                Hmac.Iguais(Assinar(tentativa.NovaMensagem), tentativa.NovaAssinatura),
                $"o SHA-512/256 cedeu com tamanho de segredo {tamanho}");
        }
    }

    [Fact(DisplayName = "a comparação em tempo constante não vaza o prefixo")]
    public void ComparacaoEmTempoConstante()
    {
        // Não dá para medir o tempo de forma confiável num teste -- foi a lição
        // de outro projeto. O que dá para afirmar é o COMPORTAMENTO: a função
        // percorre os dois vetores inteiros, então o resultado não depende de
        // onde está a primeira diferença.
        var certa = Sha256.De(Encoding.UTF8.GetBytes("mensagem"));

        // Uma errada no primeiro byte e uma errada no último. Um `==` comum
        // pararia na primeira em uma comparação e na última em 32.
        var erradaNoComeco = (byte[])certa.Clone();
        var erradaNoFim = (byte[])certa.Clone();

        erradaNoComeco[0] ^= 0xFF;
        erradaNoFim[^1] ^= 0xFF;

        Assert.False(Hmac.Iguais(certa, erradaNoComeco));
        Assert.False(Hmac.Iguais(certa, erradaNoFim));
        Assert.True(Hmac.Iguais(certa, (byte[])certa.Clone()));

        // E tamanhos diferentes saem na hora, que é aceitável: o tamanho da
        // assinatura é público.
        Assert.False(Hmac.Iguais(certa, certa[..31]));
    }

    [Fact(DisplayName = "o estado publicado é mesmo o estado interno")]
    public void OResumoEhOEstado()
    {
        // É a frase que explica o ataque inteiro, e ela dá para verificar: os
        // 32 bytes do resumo são as oito palavras do estado, em big-endian.
        var dados = Encoding.UTF8.GetBytes("qualquer mensagem de teste");

        var resumo = Sha256.De256();

        resumo.Acrescentar(dados);

        var saida = resumo.Terminar();
        var estado = resumo.Estado();

        for (var i = 0; i < 8; i++)
        {
            var doEstado = System.Buffers.Binary.BinaryPrimitives
                .ReadUInt32BigEndian(saida.AsSpan(i * 4));

            Assert.Equal(estado[i], doEstado);
        }

        // E o .NET dá o mesmo resumo, então o estado que o ataque reconstrói é
        // o estado de verdade.
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(dados)),
            Convert.ToHexString(saida));
    }
}
