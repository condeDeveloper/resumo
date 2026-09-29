namespace Conde.Resumo;

/// <summary>
/// HMAC, da RFC 2104 — a resposta certa para o problema que o
/// <see cref="Extensao"/> demonstra.
/// </summary>
/// <remarks>
/// <para>
/// A construção é curta e cada pedaço dela tem um motivo:
/// </para>
/// <code>
///   HMAC(k, m) = H( (k ⊕ opad) || H( (k ⊕ ipad) || m ) )
/// </code>
/// <para>
/// <b>Duas passadas.</b> É o que fecha a porta do ataque de extensão: o
/// resultado não é o estado interno de nada que o atacante possa continuar. A
/// mensagem entra só na passada de dentro, e o que ele veria é a saída da
/// passada de fora — que já não tem nada da mensagem para estender.
/// </para>
/// <para>
/// <b>Dois enchimentos diferentes.</b> O <c>ipad</c> é <c>0x36</c> repetido e o
/// <c>opad</c> é <c>0x5C</c>. Eles diferem em metade dos bits, e é isso que faz
/// as duas passadas usarem chaves efetivamente independentes. Se fossem iguais,
/// as duas passadas seriam a mesma coisa e a construção não valeria nada.
/// </para>
/// <para>
/// <b>A chave longa é resumida primeiro.</b> Uma chave maior que o bloco vira o
/// resumo dela. Isso tem uma consequência desconfortável e verdadeira: uma chave
/// de 100 bytes e o resumo dela de 32 bytes <b>produzem o mesmo HMAC</b>. É
/// documentado, está na RFC, e surpreende todo mundo.
/// </para>
/// <para>
/// O HMAC é de 1996 — Bellare, Canetti e Krawczyk — e foi desenhado com uma
/// prova: ele é seguro mesmo se a função de resumo tiver fraquezas de colisão.
/// Foi por isso que o HMAC-MD5 continuou aceitável anos depois de o MD5 ter
/// caído para colisões.
/// </para>
/// </remarks>
public static class Hmac
{
    private const byte Dentro = 0x36;
    private const byte Fora = 0x5C;

    /// <summary>HMAC-SHA-256.</summary>
    public static byte[] Sha256(byte[] chave, byte[] mensagem) =>
        Calcular(chave, mensagem, Resumo.Sha256.TamanhoDoBloco, dados => Resumo.Sha256.De(dados));

    /// <summary>HMAC-SHA-512.</summary>
    public static byte[] Sha512(byte[] chave, byte[] mensagem) =>
        Calcular(chave, mensagem, Resumo.Sha512.TamanhoDoBloco, dados => Resumo.Sha512.De(dados));

    /// <summary>HMAC-SHA-384.</summary>
    public static byte[] Sha384(byte[] chave, byte[] mensagem) =>
        Calcular(chave, mensagem, Resumo.Sha512.TamanhoDoBloco, dados => Resumo.Sha512.De384(dados));

    private static byte[] Calcular(byte[] chave, byte[] mensagem, int tamanhoDoBloco,
        Func<byte[], byte[]> resumir)
    {
        // Uma chave maior que o bloco vira o resumo dela -- e é por isso que a
        // chave de 100 bytes e o resumo dela de 32 dão o mesmo HMAC.
        var normalizada = chave.Length > tamanhoDoBloco ? resumir(chave) : chave;

        var deDentro = new byte[tamanhoDoBloco];
        var deFora = new byte[tamanhoDoBloco];

        // A chave curta é completada com zeros, e o ou-exclusivo com zero deixa
        // os enchimentos como estão. Não é caso especial: sai de graça.
        for (var i = 0; i < tamanhoDoBloco; i++)
        {
            var daChave = i < normalizada.Length ? normalizada[i] : (byte)0;

            deDentro[i] = (byte)(daChave ^ Dentro);
            deFora[i] = (byte)(daChave ^ Fora);
        }

        var interno = resumir(Juntar(deDentro, mensagem));

        return resumir(Juntar(deFora, interno));
    }

    private static byte[] Juntar(byte[] um, byte[] outro)
    {
        var saida = new byte[um.Length + outro.Length];

        um.CopyTo(saida, 0);
        outro.CopyTo(saida, um.Length);

        return saida;
    }

    /// <summary>
    /// Compara duas assinaturas em tempo constante.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Um <c>==</c> comum para no primeiro byte diferente, e esse "para" é
    /// mensurável. Um atacante que possa medir o tempo de resposta descobre a
    /// assinatura <b>um byte de cada vez</b>: 256 tentativas por byte, 32 bytes,
    /// oito mil tentativas — em vez das 2²⁵⁶ que a criptografia prometia.
    /// </para>
    /// <para>
    /// Não é teórico: é o ataque de Nate Lawson contra o Google Keyczar, em
    /// 2009, feito pela rede. A comparação aqui percorre os dois vetores
    /// inteiros sempre, acumulando as diferenças num ou-exclusivo.
    /// </para>
    /// </remarks>
    public static bool Iguais(byte[] um, byte[] outro)
    {
        if (um.Length != outro.Length)
        {
            return false;
        }

        var diferenca = 0;

        for (var i = 0; i < um.Length; i++)
        {
            diferenca |= um[i] ^ outro[i];
        }

        return diferenca == 0;
    }
}
