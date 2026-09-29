namespace Conde.Resumo;

/// <summary>
/// O enchimento: como uma mensagem de tamanho qualquer vira blocos inteiros.
/// </summary>
/// <remarks>
/// <para>
/// A regra é a mesma no MD5, no SHA-1 e em toda a família SHA-2, e ela tem três
/// partes, nesta ordem:
/// </para>
/// <list type="number">
///   <item><description>um byte <c>0x80</c> — um bit 1 seguido de sete zeros;</description></item>
///   <item><description>zeros, tantos quantos forem precisos;</description></item>
///   <item><description>o <b>comprimento da mensagem em bits</b>, em big-endian.</description></item>
/// </list>
/// <para>
/// Cada uma das três existe por um motivo, e o terceiro é o mais importante.
/// </para>
/// <para>
/// <b>O bit 1 obrigatório.</b> Sem ele, uma mensagem que já terminasse no
/// tamanho certo não seria enchida, e <c>"abc"</c> e <c>"abc\0"</c> poderiam
/// colidir. Ele sempre entra, mesmo quando a mensagem já é múltipla do bloco —
/// e é por isso que uma mensagem de exatamente 64 bytes gera <b>dois</b> blocos.
/// </para>
/// <para>
/// <b>O comprimento no fim.</b> É o que o Merkle–Damgård chama de
/// <i>strengthening</i>, e é o que impede uma classe inteira de colisões: sem
/// ele, duas mensagens de tamanhos diferentes que levassem o estado ao mesmo
/// lugar teriam o mesmo resumo. Com ele, mensagens de tamanhos diferentes têm
/// entradas diferentes no último bloco, sempre.
/// </para>
/// <para>
/// E é <b>esse mesmo campo</b> que torna o ataque de extensão possível: quem
/// conhece o resumo e o tamanho da mensagem sabe exatamente que enchimento foi
/// usado, e pode continuar de onde parou. A mesma decisão que fecha uma porta
/// abre a outra. Veja <see cref="Extensao"/>.
/// </para>
/// </remarks>
public static class Enchimento
{
    /// <summary>
    /// Os bytes que faltam para fechar a mensagem.
    /// </summary>
    /// <param name="totalDeBytes">Quantos bytes a mensagem tem.</param>
    /// <param name="tamanhoDoBloco">64 no SHA-256, 128 no SHA-512.</param>
    /// <param name="ondeVaiOComprimento">8 bytes no SHA-256, 16 no SHA-512.</param>
    public static byte[] Para(ulong totalDeBytes, int tamanhoDoBloco, int ondeVaiOComprimento)
    {
        // Quanto sobra no último bloco.
        var noUltimo = (int)(totalDeBytes % (ulong)tamanhoDoBloco);

        // Quantos zeros até o campo de comprimento. O `+ 1` é o byte 0x80.
        var quantosZeros = tamanhoDoBloco - ondeVaiOComprimento - 1 - noUltimo;

        if (quantosZeros < 0)
        {
            // Não coube: o enchimento atravessa para o bloco seguinte. É o caso
            // que mais pega implementação caseira, e ele acontece para toda
            // mensagem cujo resto está entre 56 e 63 bytes.
            quantosZeros += tamanhoDoBloco;
        }

        var saida = new byte[1 + quantosZeros + ondeVaiOComprimento];

        saida[0] = 0x80;

        // O comprimento em BITS, não em bytes. Multiplicar por oito aqui é o
        // que faz o campo de 64 bits comportar mensagens de 2^61 bytes -- dois
        // exabytes, que é bastante e não é infinito.
        var emBits = totalDeBytes * 8;

        for (var i = 0; i < 8; i++)
        {
            saida[^(i + 1)] = (byte)(emBits >> (i * 8));
        }

        return saida;
    }

    /// <summary>Quantos bytes o enchimento de uma mensagem deste tamanho ocupa.</summary>
    public static int Tamanho(ulong totalDeBytes, int tamanhoDoBloco, int ondeVaiOComprimento) =>
        Para(totalDeBytes, tamanhoDoBloco, ondeVaiOComprimento).Length;
}
