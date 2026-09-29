using System.Buffers.Binary;

namespace Conde.Resumo;

/// <summary>
/// SHA-512, SHA-384, SHA-512/224 e SHA-512/256, da FIPS 180-4.
/// </summary>
/// <remarks>
/// <para>
/// É o mesmo algoritmo do SHA-256 com <b>tudo dobrado</b>, e a lista de
/// diferenças é curta o bastante para caber aqui:
/// </para>
/// <list type="table">
///   <item><term>palavra</term><description>64 bits em vez de 32</description></item>
///   <item><term>bloco</term><description>128 bytes em vez de 64</description></item>
///   <item><term>rodadas</term><description>80 em vez de 64</description></item>
///   <item><term>comprimento</term><description>128 bits em vez de 64</description></item>
///   <item><term>rotações</term><description>outros números, ajustados para 64 bits</description></item>
/// </list>
/// <para>
/// E há um fato contraintuitivo: <b>o SHA-512 é mais rápido que o SHA-256</b> em
/// máquinas de 64 bits, mesmo produzindo o dobro de saída. Ele processa 128
/// bytes por 80 rodadas, contra 64 bytes por 64 rodadas — 1,6 byte por rodada
/// contra 1,0 —, e cada rodada custa o mesmo num processador que soma 64 bits de
/// uma vez. Há uma ferramenta que mede isso.
/// </para>
/// <para>
/// O SHA-512/256 existe por causa disso: é o SHA-512 truncado em 256 bits, com
/// um estado inicial próprio, e dá a mesma segurança do SHA-256 mais rápido — e
/// de quebra <b>imune ao ataque de extensão</b>, porque o resumo publicado é só
/// metade do estado interno.
/// </para>
/// </remarks>
public sealed class Sha512
{
    /// <summary>As 80 constantes: raízes cúbicas dos 80 primeiros primos.</summary>
    public static readonly ulong[] Constantes =
    [
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    ];

    public static readonly ulong[] InicialDe512 =
    [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ];

    public static readonly ulong[] InicialDe384 =
    [
        0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
        0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
    ];

    /// <summary>
    /// O estado do SHA-512/256, que é gerado por um procedimento do próprio padrão.
    /// </summary>
    /// <remarks>
    /// Ele não sai de raízes de primos: sai de rodar o SHA-512 com o estado
    /// inicial <b>invertido bit a bit</b> sobre o texto "SHA-512/256". A
    /// FIPS 180-4 descreve o procedimento na seção 5.3.6, e há um teste aqui
    /// que o refaz e confere que dá nestes valores — em vez de confiar na
    /// tabela copiada.
    /// </remarks>
    public static readonly ulong[] InicialDe512Barra256 =
    [
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
    ];

    public static readonly ulong[] InicialDe512Barra224 =
    [
        0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
    ];

    public const int TamanhoDoBloco = 128;

    private readonly ulong[] _estado;
    private readonly int _bytesDeSaida;
    private readonly byte[] _sobra = new byte[TamanhoDoBloco];

    private int _naSobra;
    private ulong _totalDeBytes;

    private Sha512(ulong[] inicial, int bytesDeSaida)
    {
        _estado = (ulong[])inicial.Clone();
        _bytesDeSaida = bytesDeSaida;
    }

    public static Sha512 De512() => new(InicialDe512, 64);

    public static Sha512 De384() => new(InicialDe384, 48);

    public static Sha512 De512Barra256() => new(InicialDe512Barra256, 32);

    public static Sha512 De512Barra224() => new(InicialDe512Barra224, 28);

    /// <summary>Roda com um estado inicial qualquer — usado para refazer as constantes.</summary>
    public static Sha512 Com(ulong[] inicial, int bytesDeSaida) => new(inicial, bytesDeSaida);

    public void Acrescentar(ReadOnlySpan<byte> dados)
    {
        _totalDeBytes += (ulong)dados.Length;

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

    public byte[] Terminar()
    {
        // O campo de comprimento tem 128 bits aqui. Os 64 de cima são sempre
        // zero para qualquer mensagem que caiba na memória deste planeta -- e
        // estão no padrão porque ele foi escrito para durar.
        Acrescentar(Enchimento.Para(_totalDeBytes, TamanhoDoBloco, ondeVaiOComprimento: 16));

        var saida = new byte[_bytesDeSaida];

        for (var i = 0; i < _bytesDeSaida; i += 8)
        {
            var palavra = _estado[i / 8];
            var quantos = Math.Min(8, _bytesDeSaida - i);

            for (var j = 0; j < quantos; j++)
            {
                saida[i + j] = (byte)(palavra >> (56 - j * 8));
            }
        }

        return saida;
    }

    public static byte[] De(ReadOnlySpan<byte> dados) => Rodar(De512(), dados);

    public static byte[] De384(ReadOnlySpan<byte> dados) => Rodar(De384(), dados);

    public static byte[] De512Barra256(ReadOnlySpan<byte> dados) =>
        Rodar(De512Barra256(), dados);

    public static byte[] De512Barra224(ReadOnlySpan<byte> dados) =>
        Rodar(De512Barra224(), dados);

    private static byte[] Rodar(Sha512 resumo, ReadOnlySpan<byte> dados)
    {
        resumo.Acrescentar(dados);

        return resumo.Terminar();
    }

    private void Misturar(ReadOnlySpan<byte> bloco)
    {
        Span<ulong> w = stackalloc ulong[80];

        for (var i = 0; i < 16; i++)
        {
            w[i] = BinaryPrimitives.ReadUInt64BigEndian(bloco[(i * 8)..]);
        }

        for (var i = 16; i < 80; i++)
        {
            // As rotações são outras: 1, 8 e 7 aqui contra 7, 18 e 3 no
            // SHA-256. Os números foram escolhidos para que a difusão cubra os
            // 64 bits no mesmo número de passos.
            var s0 = Girar(w[i - 15], 1) ^ Girar(w[i - 15], 8) ^ (w[i - 15] >> 7);
            var s1 = Girar(w[i - 2], 19) ^ Girar(w[i - 2], 61) ^ (w[i - 2] >> 6);

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

        for (var i = 0; i < 80; i++)
        {
            var somaE = Girar(e, 14) ^ Girar(e, 18) ^ Girar(e, 41);
            var escolha = (e & f) ^ (~e & g);

            var t1 = unchecked(h + somaE + escolha + Constantes[i] + w[i]);

            var somaA = Girar(a, 28) ^ Girar(a, 34) ^ Girar(a, 39);
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

    private static ulong Girar(ulong valor, int quantos) =>
        (valor >> quantos) | (valor << (64 - quantos));
}
