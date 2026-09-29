using System.Buffers.Binary;
using System.Text;

namespace Conde.Resumo;

/// <summary>
/// O ataque de extensão de comprimento — e por que o HMAC existe.
/// </summary>
/// <remarks>
/// <para>
/// É a demonstração mais útil deste projeto, porque ela mostra que uma coisa que
/// <b>parece</b> segura não é, e o "parece" é convincente.
/// </para>
/// <para>
/// Alguém quer autenticar uma mensagem. A ideia natural é juntar um segredo à
/// mensagem e resumir os dois:
/// </para>
/// <code>
///   assinatura = SHA256(segredo || mensagem)
/// </code>
/// <para>
/// Parece bom: quem não sabe o segredo não consegue calcular a assinatura. E é
/// <b>falso</b>. Quem tem a assinatura e sabe o <i>tamanho</i> do segredo pode
/// produzir a assinatura de <c>mensagem || enchimento || qualquer coisa</c>,
/// <b>sem nunca descobrir o segredo</b>.
/// </para>
/// <para>
/// O motivo está na construção de Merkle–Damgård: o resumo <b>é</b> o estado
/// interno da função no fim da mensagem. Quem o tem, tem o estado — e pode
/// continuar a partir dele como se nada tivesse acontecido.
/// </para>
/// <para>
/// Isso não é teórico. Em 2009 a API do Flickr foi quebrada assim; o mesmo vale
/// para várias APIs de assinatura da mesma época, e o padrão
/// <c>hash(chave + dados)</c> ainda aparece em código novo.
/// </para>
/// <para>
/// O <b>HMAC</b> existe exatamente por causa disto. Ele resume <b>duas</b>
/// vezes, com a chave misturada de dois jeitos diferentes:
/// </para>
/// <code>
///   HMAC(k, m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
/// </code>
/// <para>
/// A segunda passada quebra a cadeia: o resultado não é mais o estado interno de
/// nada que o atacante possa continuar. Há um teste que tenta o ataque contra o
/// HMAC e mostra que ele não anda.
/// </para>
/// </remarks>
public static class Extensao
{
    public sealed record Resultado(byte[] NovaMensagem, byte[] NovaAssinatura)
    {
        public string MensagemComoTexto =>
            string.Concat(NovaMensagem.Select(b =>
                b is >= 32 and < 127 ? ((char)b).ToString() : $"\\x{b:x2}"));
    }

    /// <summary>
    /// Estende uma assinatura <c>SHA256(segredo || mensagem)</c> sem o segredo.
    /// </summary>
    /// <param name="assinatura">O resumo que se conhece.</param>
    /// <param name="tamanhoDoSegredo">
    /// O que o atacante precisa adivinhar — e são poucas dezenas de valores.
    /// </param>
    /// <param name="mensagemOriginal">A mensagem, que é pública.</param>
    /// <param name="acrescimo">O que se quer acrescentar.</param>
    public static Resultado Estender(
        byte[] assinatura,
        int tamanhoDoSegredo,
        byte[] mensagemOriginal,
        byte[] acrescimo)
    {
        if (assinatura.Length != 32)
        {
            throw new ArgumentException("a assinatura de um SHA-256 tem 32 bytes");
        }

        // 1. O resumo É o estado interno. Ler as oito palavras de volta é todo
        //    o "ataque" -- não há nada a quebrar.
        var estado = new uint[8];

        for (var i = 0; i < 8; i++)
        {
            estado[i] = BinaryPrimitives.ReadUInt32BigEndian(assinatura.AsSpan(i * 4));
        }

        // 2. O que a vítima processou foi: segredo || mensagem || enchimento.
        //    O atacante sabe a mensagem, e o enchimento sai do TAMANHO -- que é
        //    a única coisa que ele precisa adivinhar.
        var jaProcessado = (ulong)(tamanhoDoSegredo + mensagemOriginal.Length);

        var enchimentoDaVitima = Enchimento.Para(
            jaProcessado, Sha256.TamanhoDoBloco, ondeVaiOComprimento: 8);

        var totalAteAqui = jaProcessado + (ulong)enchimentoDaVitima.Length;

        // 3. Continua de onde a vítima parou.
        var resumo = Sha256.Continuando(estado, totalAteAqui);

        resumo.Acrescentar(acrescimo);

        // 4. A mensagem nova é a antiga mais o enchimento mais o acréscimo. Ela
        //    tem bytes estranhos no meio, e a maioria dos formatos os ignora --
        //    que é o que torna o ataque prático.
        var nova = new byte[mensagemOriginal.Length + enchimentoDaVitima.Length + acrescimo.Length];

        mensagemOriginal.CopyTo(nova, 0);
        enchimentoDaVitima.CopyTo(nova, mensagemOriginal.Length);
        acrescimo.CopyTo(nova, mensagemOriginal.Length + enchimentoDaVitima.Length);

        return new Resultado(nova, resumo.Terminar());
    }

    /// <summary>
    /// A assinatura ingênua, que este ataque quebra.
    /// </summary>
    /// <remarks>
    /// Está aqui com este nome de propósito. Ela existe em código de verdade, e
    /// ver as duas lado a lado — esta e o HMAC — é o que faz a diferença entrar.
    /// </remarks>
    public static byte[] AssinaturaIngenua(byte[] segredo, byte[] mensagem)
    {
        var resumo = Sha256.De256();

        resumo.Acrescentar(segredo);
        resumo.Acrescentar(mensagem);

        return resumo.Terminar();
    }

    /// <summary>Tenta adivinhar o tamanho do segredo, testando valores.</summary>
    /// <remarks>
    /// Na prática o atacante nem precisa adivinhar direito de primeira: ele
    /// testa de 1 a 64 e vê qual assinatura o servidor aceita. São 64 tentativas
    /// — nada.
    /// </remarks>
    public static int? DescobrirTamanhoDoSegredo(
        byte[] assinatura,
        byte[] mensagemOriginal,
        byte[] acrescimo,
        Func<byte[], byte[], bool> oServidorAceita,
        int ate = 64)
    {
        for (var tamanho = 1; tamanho <= ate; tamanho++)
        {
            var tentativa = Estender(assinatura, tamanho, mensagemOriginal, acrescimo);

            if (oServidorAceita(tentativa.NovaMensagem, tentativa.NovaAssinatura))
            {
                return tamanho;
            }
        }

        return null;
    }

    public static byte[] Texto(string texto) => Encoding.UTF8.GetBytes(texto);
}
