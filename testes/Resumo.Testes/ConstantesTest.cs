using System.Numerics;
using System.Text;
using Xunit;

namespace Conde.Resumo.Testes;

/// <summary>
/// As 152 constantes do padrão, <b>recalculadas</b> em vez de copiadas.
/// </summary>
/// <remarks>
/// <para>
/// As constantes do SHA-2 não saem do nada, e é deliberado: elas são a parte
/// fracionária de raízes de primos pequenos. Isso tem nome —
/// <i>nothing-up-my-sleeve numbers</i>, números de quem não tem nada na manga —
/// e existe para que <b>qualquer pessoa possa recalculá-las</b> e ver que
/// ninguém escolheu valores com uma fraqueza escondida dentro.
/// </para>
/// <para>
/// A preocupação não é paranoia: em 1975 a NSA mexeu nas caixas de substituição
/// do DES sem explicar por quê, e o mundo passou vinte anos desconfiando. Em
/// 1994 descobriu-se que as mudanças o <b>fortaleciam</b> contra um ataque que
/// ainda era segredo — e a lição que ficou foi outra: uma constante
/// inexplicada, mesmo boa, custa vinte anos de confiança.
/// </para>
/// <para>
/// Este arquivo faz o que a explicação promete. Ele calcula as raízes com
/// aritmética inteira exata, sem ponto flutuante, e confere as 152 uma a uma.
/// É a diferença entre "está escrito que vem das raízes cúbicas" e saber que
/// vem.
/// </para>
/// </remarks>
public class ConstantesTest
{
    /// <summary>Os primeiros primos, por divisões sucessivas.</summary>
    private static IEnumerable<int> Primos()
    {
        var achados = new List<int>();

        for (var n = 2; ; n++)
        {
            var eh = true;

            foreach (var primo in achados)
            {
                if ((long)primo * primo > n)
                {
                    break;
                }

                if (n % primo == 0)
                {
                    eh = false;
                    break;
                }
            }

            if (eh)
            {
                achados.Add(n);

                yield return n;
            }
        }
    }

    /// <summary>
    /// Os <paramref name="bits"/> de cima da parte fracionária de <c>n^(1/raiz)</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Com ponto flutuante isto não funciona: um <c>double</c> tem 52 bits de
    /// mantissa, e são precisos 64 da parte fracionária com precisão total. A
    /// conta é feita com inteiros grandes.
    /// </para>
    /// <para>
    /// O truque: para achar os primeiros <c>b</c> bits da fração de <c>n^(1/r)</c>,
    /// calcula-se a raiz <c>r</c>-ésima inteira de <c>n · 2^(b·r)</c>. O
    /// deslocamento leva a fração para dentro do inteiro antes de a raiz a
    /// perder.
    /// </para>
    /// </remarks>
    private static ulong FracaoDaRaiz(int n, int raiz, int bits)
    {
        var deslocado = new BigInteger(n) * BigInteger.Pow(2, bits * raiz);

        var inteira = RaizInteira(deslocado, raiz);

        // A parte inteira da raiz de n, deslocada pelos mesmos bits, é o que
        // sobra depois de tirar a fração.
        var parteInteira = RaizInteira(new BigInteger(n), raiz);

        var fracao = inteira - parteInteira * BigInteger.Pow(2, bits);

        return (ulong)fracao;
    }

    /// <summary>A raiz <paramref name="raiz"/>-ésima inteira, por bisseção.</summary>
    private static BigInteger RaizInteira(BigInteger valor, int raiz)
    {
        if (valor < 2)
        {
            return valor;
        }

        var baixo = BigInteger.One;
        var alto = BigInteger.One << (int)(valor.GetBitLength() / raiz + 2);

        while (baixo < alto)
        {
            var meio = (baixo + alto + 1) / 2;

            if (BigInteger.Pow(meio, raiz) <= valor)
            {
                baixo = meio;
            }
            else
            {
                alto = meio - 1;
            }
        }

        return baixo;
    }

    [Fact(DisplayName = "o estado inicial do SHA-256: raízes quadradas dos 8 primeiros primos")]
    public void EstadoInicialDe256()
    {
        var primos = Primos().Take(8).ToArray();

        for (var i = 0; i < 8; i++)
        {
            Assert.Equal(
                Sha256.InicialDe256[i],
                (uint)FracaoDaRaiz(primos[i], raiz: 2, bits: 32));
        }
    }

    [Fact(DisplayName = "as 64 constantes do SHA-256: raízes cúbicas dos 64 primeiros primos")]
    public void ConstantesDe256()
    {
        var primos = Primos().Take(64).ToArray();

        for (var i = 0; i < 64; i++)
        {
            Assert.Equal(
                Sha256.Constantes[i],
                (uint)FracaoDaRaiz(primos[i], raiz: 3, bits: 32));
        }
    }

    [Fact(DisplayName = "o estado inicial do SHA-512: os mesmos primos, com 64 bits")]
    public void EstadoInicialDe512()
    {
        var primos = Primos().Take(8).ToArray();

        for (var i = 0; i < 8; i++)
        {
            Assert.Equal(
                Sha512.InicialDe512[i],
                FracaoDaRaiz(primos[i], raiz: 2, bits: 64));
        }
    }

    [Fact(DisplayName = "as 80 constantes do SHA-512")]
    public void ConstantesDe512()
    {
        var primos = Primos().Take(80).ToArray();

        for (var i = 0; i < 80; i++)
        {
            Assert.Equal(
                Sha512.Constantes[i],
                FracaoDaRaiz(primos[i], raiz: 3, bits: 64));
        }
    }

    [Fact(DisplayName = "o estado do SHA-384: do 9º ao 16º primo")]
    public void EstadoInicialDe384()
    {
        // O SHA-384 usa os primos SEGUINTES, e não os mesmos, pelo mesmo motivo
        // do SHA-224: se usasse os mesmos, o resumo de 384 bits seria um prefixo
        // do de 512, e quem tivesse um saberia metade do outro.
        var primos = Primos().Skip(8).Take(8).ToArray();

        for (var i = 0; i < 8; i++)
        {
            Assert.Equal(
                Sha512.InicialDe384[i],
                FracaoDaRaiz(primos[i], raiz: 2, bits: 64));
        }
    }

    [Fact(DisplayName = "o estado do SHA-224: os 32 bits do MEIO, do 9º ao 16º primo")]
    public void EstadoInicialDe224()
    {
        // Esta é a mais estranha do padrão: são os bits 32 a 63 da fração, e não
        // os 32 de cima. O motivo é que os 32 de cima já estão no SHA-384 --
        // então o SHA-224 pega a metade de baixo dos mesmos números.
        var primos = Primos().Skip(8).Take(8).ToArray();

        for (var i = 0; i < 8; i++)
        {
            var completo = FracaoDaRaiz(primos[i], raiz: 2, bits: 64);

            Assert.Equal(Sha256.InicialDe224[i], (uint)(completo & 0xFFFFFFFF));
        }
    }

    [Fact(DisplayName = "o estado do SHA-512/256, gerado pelo procedimento da FIPS")]
    public void EstadoDe512Barra256()
    {
        // Este não sai de primos: sai de rodar o SHA-512 com o estado inicial
        // INVERTIDO bit a bit sobre o texto "SHA-512/256". A FIPS 180-4 descreve
        // o procedimento na seção 5.3.6, e refazê-lo aqui é a única forma de
        // saber que a tabela copiada está certa.
        var invertido = Sha512.InicialDe512.Select(x => x ^ 0xA5A5A5A5A5A5A5A5).ToArray();

        var gerador = Sha512.Com(invertido, 64);

        gerador.Acrescentar(Encoding.UTF8.GetBytes("SHA-512/256"));

        var saida = gerador.Terminar();

        for (var i = 0; i < 8; i++)
        {
            var palavra = System.Buffers.Binary.BinaryPrimitives
                .ReadUInt64BigEndian(saida.AsSpan(i * 8));

            Assert.Equal(Sha512.InicialDe512Barra256[i], palavra);
        }
    }

    [Fact(DisplayName = "o estado do SHA-512/224, pelo mesmo procedimento")]
    public void EstadoDe512Barra224()
    {
        var invertido = Sha512.InicialDe512.Select(x => x ^ 0xA5A5A5A5A5A5A5A5).ToArray();

        var gerador = Sha512.Com(invertido, 64);

        gerador.Acrescentar(Encoding.UTF8.GetBytes("SHA-512/224"));

        var saida = gerador.Terminar();

        for (var i = 0; i < 8; i++)
        {
            var palavra = System.Buffers.Binary.BinaryPrimitives
                .ReadUInt64BigEndian(saida.AsSpan(i * 8));

            Assert.Equal(Sha512.InicialDe512Barra224[i], palavra);
        }
    }

    [Fact(DisplayName = "o efeito avalanche: um bit muda metade da saída")]
    public void Avalanche()
    {
        // É o que uma função de resumo promete, e dá para medir. Trocar UM bit
        // da entrada tem de mudar, em média, METADE dos bits da saída -- 128 dos
        // 256. Se mudasse menos, haveria estrutura para um atacante explorar.
        var sorteio = new Random(20260929);

        var total = 0;
        var quantas = 0;

        for (var i = 0; i < 2_000; i++)
        {
            var dados = new byte[sorteio.Next(1, 100)];

            sorteio.NextBytes(dados);

            var antes = Sha256.De(dados);

            var mexido = (byte[])dados.Clone();

            mexido[sorteio.Next(mexido.Length)] ^= (byte)(1 << sorteio.Next(8));

            var depois = Sha256.De(mexido);

            var mudaram = 0;

            for (var j = 0; j < 32; j++)
            {
                mudaram += System.Numerics.BitOperations.PopCount((uint)(antes[j] ^ depois[j]));
            }

            total += mudaram;
            quantas++;
        }

        var media = (double)total / quantas;

        // A margem é folgada: o desvio padrão de 256 moedas é 8, então 128 ± 6
        // é confortável para uma média de duas mil amostras.
        Assert.InRange(media, 122, 134);
    }
}
