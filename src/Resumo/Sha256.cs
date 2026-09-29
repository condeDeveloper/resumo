using System.Buffers.Binary;

namespace Conde.Resumo;

/// <summary>
/// SHA-256 e SHA-224, da FIPS 180-4.
/// </summary>
/// <remarks>
/// <para>
/// A construção é a de Merkle e Damgård, de 1979: a mensagem é partida em blocos
/// de tamanho fixo, e um <b>estado</b> de tamanho fixo é misturado com cada
/// bloco, um depois do outro. O estado final é o resumo.
/// </para>
/// <code>
///   estado inicial ──► [bloco 1] ──► [bloco 2] ──► ... ──► resumo
/// </code>
/// <para>
/// A parte que dá segurança é a função que mistura: 64 rodadas de rotações,
/// deslocamentos e somas, desenhadas para que trocar <b>um bit</b> da entrada
/// mude metade dos bits da saída. O efeito tem nome — avalanche — e há um teste
/// que o mede.
/// </para>
/// <para>
/// O que nunca é óbvio de onde vem: as constantes. As oito do estado inicial são
/// os 32 primeiros bits da parte fracionária das <b>raízes quadradas</b> dos
/// oito primeiros primos; as 64 de rodada são os das <b>raízes cúbicas</b> dos
/// 64 primeiros primos. Isso é deliberado e tem nome: <i>nothing-up-my-sleeve</i>
/// — números que qualquer pessoa pode recalcular, para que ninguém possa ter
/// escolhido valores com uma fraqueza escondida dentro. Há um teste que recalcula
/// todas as 72.
/// </para>
/// </remarks>
public sealed class Sha256
{
    /// <summary>
    /// As 64 constantes de rodada: os 32 bits de cima da parte fracionária das
    /// raízes cúbicas dos 64 primeiros primos.
    /// </summary>
    public static readonly uint[] Constantes =
    [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];

    /// <summary>
    /// O estado inicial do SHA-256: raízes quadradas dos oito primeiros primos.
    /// </summary>
    public static readonly uint[] InicialDe256 =
    [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    /// <summary>
    /// O estado inicial do SHA-224 — e ele é a coisa mais estranha do padrão.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SHA-224 é SHA-256 com <b>outro estado inicial</b> e a saída cortada em
    /// 224 bits. Os valores são os 32 bits do <i>meio</i> das raízes quadradas
    /// do nono ao décimo sexto primo.
    /// </para>
    /// <para>
    /// Por que não simplesmente cortar o SHA-256? Porque aí o SHA-224 de uma
    /// mensagem seria um prefixo do SHA-256 dela, e quem tivesse um saberia o
    /// outro pela metade. O estado diferente separa completamente as duas
    /// funções — é barato e resolve.
    /// </para>
    /// </remarks>
    public static readonly uint[] InicialDe224 =
    [
        0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
    ];

    public const int TamanhoDoBloco = 64;

    private readonly uint[] _estado;
    private readonly int _bytesDeSaida;
    private readonly byte[] _sobra = new byte[TamanhoDoBloco];

    private int _naSobra;
    private ulong _totalDeBytes;

    private Sha256(uint[] inicial, int bytesDeSaida)
    {
        _estado = (uint[])inicial.Clone();
        _bytesDeSaida = bytesDeSaida;
    }

    public static Sha256 De256() => new(InicialDe256, 32);

    public static Sha256 De224() => new(InicialDe224, 28);

    /// <summary>
    /// Começa de um estado qualquer, com um total de bytes qualquer.
    /// </summary>
    /// <remarks>
    /// Isto <b>não</b> é uma conveniência: é o que torna o ataque de extensão de
    /// comprimento possível, e é por isso que está aqui, exposto, com este
    /// comentário. A construção de Merkle–Damgård expõe o estado interno no
    /// resumo — quem tem o resumo tem o estado — e daí o resto sai sozinho.
    /// Veja <see cref="Extensao"/>.
    /// </remarks>
    public static Sha256 Continuando(uint[] estado, ulong bytesJaProcessados)
    {
        if (estado.Length != 8)
        {
            throw new ArgumentException("o estado do SHA-256 tem oito palavras");
        }

        return new Sha256(estado, 32) { _totalDeBytes = bytesJaProcessados };
    }

    public void Acrescentar(ReadOnlySpan<byte> dados)
    {
        _totalDeBytes += (ulong)dados.Length;

        // Se havia sobra, completa o bloco com o começo dos dados novos.
        if (_naSobra > 0)
        {
            var falta = Math.Min(TamanhoDoBloco - _naSobra, dados.Length);

            dados[..falta].CopyTo(_sobra.AsSpan(_naSobra));

            _naSobra += falta;
            dados = dados[falta..];

            if (_naSobra == TamanhoDoBloco)
            {
                Misturar(_sobra);
                _naSobra = 0;
            }
        }

        while (dados.Length >= TamanhoDoBloco)
        {
            Misturar(dados[..TamanhoDoBloco]);
            dados = dados[TamanhoDoBloco..];
        }

        if (dados.Length > 0)
        {
            dados.CopyTo(_sobra);
            _naSobra = dados.Length;
        }
    }

    /// <summary>Fecha a conta e devolve o resumo.</summary>
    public byte[] Terminar()
    {
        var enchimento = Enchimento.Para(_totalDeBytes, TamanhoDoBloco, ondeVaiOComprimento: 8);

        Acrescentar(enchimento);

        var saida = new byte[_bytesDeSaida];

        for (var i = 0; i < _bytesDeSaida; i += 4)
        {
            var palavra = _estado[i / 4];
            var quantos = Math.Min(4, _bytesDeSaida - i);

            // Big-endian: o SHA é de 1993, quando "ordem de rede" era a escolha
            // óbvia para qualquer coisa que fosse atravessar um fio.
            for (var j = 0; j < quantos; j++)
            {
                saida[i + j] = (byte)(palavra >> (24 - j * 8));
            }
        }

        return saida;
    }

    /// <summary>O estado interno, que é o que o resumo expõe.</summary>
    public uint[] Estado() => (uint[])_estado.Clone();

    public static byte[] De(ReadOnlySpan<byte> dados)
    {
        var resumo = De256();

        resumo.Acrescentar(dados);

        return resumo.Terminar();
    }

    public static byte[] De224(ReadOnlySpan<byte> dados)
    {
        var resumo = De224();

        resumo.Acrescentar(dados);

        return resumo.Terminar();
    }

    /// <summary>
    /// A função de compressão: 64 rodadas sobre um bloco de 64 bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// É o coração do algoritmo, e tem duas metades.
    /// </para>
    /// <para>
    /// A primeira <b>expande</b> os 16 palavras do bloco em 64, cada nova sendo
    /// uma mistura de quatro anteriores. É o que faz um bit do começo do bloco
    /// influenciar todas as rodadas — sem a expansão, os últimos bytes do bloco
    /// passariam por muito menos mistura que os primeiros.
    /// </para>
    /// <para>
    /// A segunda roda 64 vezes sobre oito palavras de trabalho, e a cada rodada
    /// duas delas são recalculadas e as outras seis <b>andam de lado</b>. É um
    /// registrador de deslocamento com realimentação, e o efeito é que uma
    /// mudança leva umas poucas rodadas para alcançar todas as palavras — daí as
    /// 64, que dão folga de sobra.
    /// </para>
    /// </remarks>
    private void Misturar(ReadOnlySpan<byte> bloco)
    {
        Span<uint> w = stackalloc uint[64];

        for (var i = 0; i < 16; i++)
        {
            w[i] = BinaryPrimitives.ReadUInt32BigEndian(bloco[(i * 4)..]);
        }

        for (var i = 16; i < 64; i++)
        {
            var s0 = Girar(w[i - 15], 7) ^ Girar(w[i - 15], 18) ^ (w[i - 15] >> 3);
            var s1 = Girar(w[i - 2], 17) ^ Girar(w[i - 2], 19) ^ (w[i - 2] >> 10);

            w[i] = unchecked(w[i - 16] + s0 + w[i - 7] + s1);
        }

        var a = _estado[0];
        var b = _estado[1];
        var c = _estado[2];
        var d = _estado[3];
        var e = _estado[4];
        var f = _estado[5];
        var g = _estado[6];
        var h = _estado[7];

        for (var i = 0; i < 64; i++)
        {
            var somaE = Girar(e, 6) ^ Girar(e, 11) ^ Girar(e, 25);

            // "Escolha": para cada bit, o `e` decide se sai o `f` ou o `g`.
            var escolha = (e & f) ^ (~e & g);

            var t1 = unchecked(h + somaE + escolha + Constantes[i] + w[i]);

            var somaA = Girar(a, 2) ^ Girar(a, 13) ^ Girar(a, 22);

            // "Maioria": para cada bit, o que aparece em pelo menos dois dos três.
            var maioria = (a & b) ^ (a & c) ^ (b & c);

            var t2 = unchecked(somaA + maioria);

            h = g;
            g = f;
            f = e;
            e = unchecked(d + t1);
            d = c;
            c = b;
            b = a;
            a = unchecked(t1 + t2);
        }

        // A soma no fim é o que impede a função de ser invertível: sem ela,
        // conhecer a saída daria a entrada de volta rodando as 64 ao contrário.
        // É a construção de Davies–Meyer, e é ela que transforma uma cifra
        // reversível numa função de mão única.
        unchecked
        {
            _estado[0] += a;
            _estado[1] += b;
            _estado[2] += c;
            _estado[3] += d;
            _estado[4] += e;
            _estado[5] += f;
            _estado[6] += g;
            _estado[7] += h;
        }
    }

    private static uint Girar(uint valor, int quantos) =>
        (valor >> quantos) | (valor << (32 - quantos));
}
