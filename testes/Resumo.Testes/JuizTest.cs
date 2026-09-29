using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Conde.Resumo.Testes;

/// <summary>
/// O juiz: o <c>System.Security.Cryptography</c> do .NET.
/// </summary>
/// <remarks>
/// <para>
/// É um juiz de uma qualidade rara: além de ser uma implementação madura, ela é
/// <b>validada pelo programa CMVP do NIST</b> — passou pelos vetores oficiais
/// num laboratório credenciado. Comparar com ela é comparar com o padrão,
/// indiretamente.
/// </para>
/// <para>
/// E o que se prova é o que mais importa numa função de resumo: uma
/// implementação com defeito <b>não estoura</b>. Ela devolve 32 bytes que
/// parecem perfeitamente aleatórios e não são o resumo de nada — e passam por
/// qualquer conferência a olho. Só a comparação com outra implementação pega.
/// </para>
/// </remarks>
public class JuizTest
{
    private static string Hexa(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>
    /// Os tamanhos que cobrem todos os caminhos do enchimento.
    /// </summary>
    /// <remarks>
    /// O enchimento é onde uma implementação caseira erra, e ele tem três casos:
    /// cabe no bloco, não cabe e atravessa para o seguinte, e a mensagem já é
    /// múltipla do bloco. Os tamanhos em torno de 55, 56, 63, 64 e 65 exercitam
    /// os três — e o 56 é o mais famoso, porque é onde o campo de comprimento
    /// deixa de caber.
    /// </remarks>
    public static TheoryData<int> TamanhosDificeis()
    {
        var dados = new TheoryData<int>();

        foreach (var tamanho in (int[])
                 [0, 1, 2, 3, 54, 55, 56, 57, 63, 64, 65,
                  111, 112, 113, 119, 120, 127, 128, 129,
                  191, 192, 255, 256, 1000, 1023, 1024, 1025])
        {
            dados.Add(tamanho);
        }

        return dados;
    }

    [Theory(DisplayName = "SHA-256 nos tamanhos que quebram o enchimento")]
    [MemberData(nameof(TamanhosDificeis))]
    public void Sha256NosTamanhosDificeis(int tamanho)
    {
        var dados = new byte[tamanho];

        new Random(tamanho).NextBytes(dados);

        Assert.Equal(Hexa(SHA256.HashData(dados)), Hexa(Sha256.De(dados)));
    }

    [Theory(DisplayName = "SHA-512 nos tamanhos que quebram o enchimento")]
    [MemberData(nameof(TamanhosDificeis))]
    public void Sha512NosTamanhosDificeis(int tamanho)
    {
        var dados = new byte[tamanho];

        new Random(tamanho).NextBytes(dados);

        Assert.Equal(Hexa(SHA512.HashData(dados)), Hexa(Sha512.De(dados)));
    }

    [Fact(DisplayName = "cem mil mensagens sorteadas, nas quatro funções")]
    public void CemMilMensagens()
    {
        var sorteio = new Random(20260929);

        for (var i = 0; i < 100_000; i++)
        {
            var dados = new byte[sorteio.Next(0, 300)];

            sorteio.NextBytes(dados);

            Assert.Equal(Hexa(SHA256.HashData(dados)), Hexa(Sha256.De(dados)));
            Assert.Equal(Hexa(SHA512.HashData(dados)), Hexa(Sha512.De(dados)));

            if (i % 10 == 0)
            {
                Assert.Equal(Hexa(SHA384.HashData(dados)), Hexa(Sha512.De384(dados)));
                Assert.Equal(Hexa(SHA256.HashData(dados)), Hexa(Sha256.De(dados)));
            }
        }
    }

    [Fact(DisplayName = "SHA-224, que o .NET não tem, contra os vetores da FIPS")]
    public void Sha224()
    {
        // O .NET não implementa SHA-224, então aqui o juiz volta a ser a
        // especificação: os dois vetores do apêndice da FIPS 180-4.
        Assert.Equal(
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            Hexa(Sha256.De224(Encoding.UTF8.GetBytes("abc"))));

        Assert.Equal(
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            Hexa(Sha256.De224(Encoding.UTF8.GetBytes(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))));

        // E o do texto vazio.
        Assert.Equal(
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            Hexa(Sha256.De224([])));
    }

    [Fact(DisplayName = "os vetores impressos na FIPS 180-4")]
    public void OsVetoresDaFips()
    {
        // Nenhum destes números é meu: estão nos apêndices do padrão, calculados
        // pelo NIST antes de este código existir.
        (Func<byte[], byte[]> Funcao, string Entrada, string Esperado)[] casos =
        [
            (d => Sha256.De(d), "abc",
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),

            (d => Sha256.De(d), "",
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),

            (d => Sha256.De(d),
             "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),

            (d => Sha512.De(d), "abc",
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
             + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),

            (d => Sha512.De(d), "",
             "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
             + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),

            (d => Sha512.De384(d), "abc",
             "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
             + "8086072ba1e7cc2358baeca134c825a7"),

            (d => Sha512.De512Barra256(d), "abc",
             "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),

            (d => Sha512.De512Barra224(d), "abc",
             "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
        ];

        foreach (var (funcao, entrada, esperado) in casos)
        {
            Assert.Equal(esperado, Hexa(funcao(Encoding.UTF8.GetBytes(entrada))));
        }
    }

    [Fact(DisplayName = "o milhão de letras 'a'")]
    public void OMilhaoDeLetras()
    {
        // É o terceiro vetor do padrão, e ele existe para pegar erros de
        // contagem: um milhão de bytes são 15.625 blocos, e um estouro no
        // contador ou um erro no campo de comprimento aparece aqui e em mais
        // lugar nenhum.
        var dados = Encoding.UTF8.GetBytes(new string('a', 1_000_000));

        Assert.Equal(
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            Hexa(Sha256.De(dados)));

        Assert.Equal(
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
            + "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
            Hexa(Sha512.De(dados)));

        Assert.Equal(Hexa(SHA256.HashData(dados)), Hexa(Sha256.De(dados)));
    }

    [Fact(DisplayName = "acrescentar em pedaços dá o mesmo que de uma vez")]
    public void EmPedacos()
    {
        // Um resumo em fluxo tem de dar o mesmo que um de uma vez, para
        // QUALQUER divisão dos dados. É onde mora o defeito de quem guarda mal
        // a sobra entre as chamadas -- e ele só aparece quando o corte cai no
        // meio de um bloco.
        var sorteio = new Random(7);

        for (var i = 0; i < 5_000; i++)
        {
            var dados = new byte[sorteio.Next(0, 500)];

            sorteio.NextBytes(dados);

            var deUmaVez = Sha256.De(dados);

            var emPedacos = Sha256.De256();
            var posicao = 0;

            while (posicao < dados.Length)
            {
                var quanto = Math.Min(sorteio.Next(1, 100), dados.Length - posicao);

                emPedacos.Acrescentar(dados.AsSpan(posicao, quanto));

                posicao += quanto;
            }

            Assert.Equal(Hexa(deUmaVez), Hexa(emPedacos.Terminar()));
        }
    }

    [Fact(DisplayName = "HMAC-SHA-256 e HMAC-SHA-512 contra os do .NET")]
    public void HmacContraODotnet()
    {
        var sorteio = new Random(11);

        for (var i = 0; i < 20_000; i++)
        {
            // Os tamanhos de chave cobrem os três caminhos: menor que o bloco,
            // igual ao bloco, e maior (que é resumida antes).
            var chave = new byte[sorteio.Next(0, 200)];
            var mensagem = new byte[sorteio.Next(0, 200)];

            sorteio.NextBytes(chave);
            sorteio.NextBytes(mensagem);

            Assert.Equal(
                Hexa(HMACSHA256.HashData(chave, mensagem)),
                Hexa(Hmac.Sha256(chave, mensagem)));

            if (i % 4 == 0)
            {
                Assert.Equal(
                    Hexa(HMACSHA512.HashData(chave, mensagem)),
                    Hexa(Hmac.Sha512(chave, mensagem)));

                Assert.Equal(
                    Hexa(HMACSHA384.HashData(chave, mensagem)),
                    Hexa(Hmac.Sha384(chave, mensagem)));
            }
        }
    }

    [Fact(DisplayName = "uma chave longa e o resumo dela dão o mesmo HMAC")]
    public void AChaveLongaViraOResumo()
    {
        // É documentado, está na RFC 2104, e surpreende todo mundo: uma chave
        // maior que o bloco é resumida antes, então ela e o resumo dela são a
        // mesma chave.
        var sorteio = new Random(13);

        var longa = new byte[100];

        sorteio.NextBytes(longa);

        var curta = Sha256.De(longa);
        var mensagem = Encoding.UTF8.GetBytes("qualquer coisa");

        Assert.Equal(
            Hexa(Hmac.Sha256(longa, mensagem)),
            Hexa(Hmac.Sha256(curta, mensagem)));

        // E o .NET concorda, o que prova que não é peculiaridade daqui.
        Assert.Equal(
            Hexa(HMACSHA256.HashData(longa, mensagem)),
            Hexa(HMACSHA256.HashData(curta, mensagem)));
    }
}
