using System.Text;
using Conde.Resumo;

namespace Conde.Resumo.Ferramentas.Cli;

/// <summary>
/// A linha de comando — incluindo o ataque, para ver acontecer.
/// </summary>
/// <remarks>
/// O comando <c>ataque</c> é o motivo de a ferramenta existir. Ler que
/// <c>hash(segredo + mensagem)</c> é inseguro convence menos que ver a mensagem
/// forjada aparecer na tela com o servidor aceitando.
/// </remarks>
public static class Programa
{
    public static int Main(string[] argumentos)
    {
        // Procura o comando entre TODOS os argumentos, e não só no primeiro.
        // O `dotnet run` nem sempre entrega apenas o que vem depois do `--`, e
        // um `argumentos[0]` cru fazia a ferramenta cair no "não conheço" e sair
        // com código 1 -- derrubando o CI com o código todo funcionando.
        var comandos = new[] { "resumir", "arquivo", "hmac", "ataque" };

        var onde = Array.FindIndex(argumentos, a => comandos.Contains(a));

        if (onde < 0)
        {
            if (argumentos.Length > 0)
            {
                Console.Error.WriteLine($"não conheço o comando {argumentos[0]}");
            }

            Console.WriteLine(Ajuda);

            return 1;
        }

        var resto = argumentos[onde..];

        return resto[0] switch
        {
            "resumir" => Resumir(resto),
            "arquivo" => Arquivo(resto),
            "hmac" => Hmac(resto),
            _ => Ataque(),
        };
    }

    private static string Hexa(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static int Resumir(string[] argumentos)
    {
        var texto = argumentos.Length > 1
            ? argumentos[1]
            : Console.In.ReadToEnd();

        var dados = Encoding.UTF8.GetBytes(texto);

        Mostrar(dados);

        return 0;
    }

    private static int Arquivo(string[] argumentos)
    {
        if (argumentos.Length < 2)
        {
            Console.Error.WriteLine("falta o arquivo");

            return 1;
        }

        byte[] dados;

        try
        {
            dados = File.ReadAllBytes(argumentos[1]);
        }
        catch (IOException erro)
        {
            Console.Error.WriteLine(erro.Message);

            return 2;
        }

        Console.WriteLine($"{argumentos[1]}: {dados.Length} byte(s)");
        Console.WriteLine();

        Mostrar(dados);

        return 0;
    }

    private static void Mostrar(byte[] dados)
    {
        Console.WriteLine($"  sha-224       {Hexa(Sha256.De224(dados))}");
        Console.WriteLine($"  sha-256       {Hexa(Sha256.De(dados))}");
        Console.WriteLine($"  sha-384       {Hexa(Sha512.De384(dados))}");
        Console.WriteLine($"  sha-512       {Hexa(Sha512.De(dados))}");
        Console.WriteLine($"  sha-512/224   {Hexa(Sha512.De512Barra224(dados))}");
        Console.WriteLine($"  sha-512/256   {Hexa(Sha512.De512Barra256(dados))}");
    }

    private static int Hmac(string[] argumentos)
    {
        if (argumentos.Length < 3)
        {
            Console.Error.WriteLine("uso: hmac CHAVE MENSAGEM");

            return 1;
        }

        var chave = Encoding.UTF8.GetBytes(argumentos[1]);
        var mensagem = Encoding.UTF8.GetBytes(argumentos[2]);

        Console.WriteLine($"  hmac-sha-256  {Hexa(Resumo.Hmac.Sha256(chave, mensagem))}");
        Console.WriteLine($"  hmac-sha-384  {Hexa(Resumo.Hmac.Sha384(chave, mensagem))}");
        Console.WriteLine($"  hmac-sha-512  {Hexa(Resumo.Hmac.Sha512(chave, mensagem))}");

        return 0;
    }

    private static int Ataque()
    {
        var segredo = Encoding.UTF8.GetBytes("um segredo de 24 bytes!!");
        var mensagem = Encoding.UTF8.GetBytes("usuario=joao&admin=nao");
        var acrescimo = Encoding.UTF8.GetBytes("&admin=sim");

        Console.WriteLine("O servidor assina assim:  SHA256(segredo || mensagem)");
        Console.WriteLine();
        Console.WriteLine($"  segredo    (só o servidor sabe, {segredo.Length} bytes)");
        Console.WriteLine($"  mensagem   {Encoding.UTF8.GetString(mensagem)}");

        var assinatura = Extensao.AssinaturaIngenua(segredo, mensagem);

        Console.WriteLine($"  assinatura {Hexa(assinatura)}");
        Console.WriteLine();
        Console.WriteLine("O atacante vê só a mensagem e a assinatura. Ele quer");
        Console.WriteLine($"acrescentar \"{Encoding.UTF8.GetString(acrescimo)}\" e não sabe o segredo.");
        Console.WriteLine();

        // Ele não sabe o tamanho: descobre testando.
        var descoberto = Extensao.DescobrirTamanhoDoSegredo(
            assinatura, mensagem, acrescimo,
            (m, a) => Resumo.Hmac.Iguais(Extensao.AssinaturaIngenua(segredo, m), a));

        if (descoberto is null)
        {
            Console.WriteLine("o ataque não funcionou -- o que seria uma surpresa.");

            return 1;
        }

        var forjado = Extensao.Estender(assinatura, descoberto.Value, mensagem, acrescimo);

        Console.WriteLine($"  tamanho do segredo descoberto em {descoberto} tentativas");
        Console.WriteLine();
        Console.WriteLine("  mensagem forjada:");
        Console.WriteLine($"    {forjado.MensagemComoTexto}");
        Console.WriteLine();
        Console.WriteLine($"  assinatura forjada: {Hexa(forjado.NovaAssinatura)}");
        Console.WriteLine($"  o servidor calcula: {Hexa(Extensao.AssinaturaIngenua(segredo, forjado.NovaMensagem))}");
        Console.WriteLine();
        Console.WriteLine("  ACEITA. E o segredo nunca foi descoberto.");
        Console.WriteLine();
        Console.WriteLine("Com HMAC, o mesmo ataque:");
        Console.WriteLine();

        var comHmac = Resumo.Hmac.Sha256(segredo, mensagem);

        var tentativa = Extensao.DescobrirTamanhoDoSegredo(
            comHmac, mensagem, acrescimo,
            (m, a) => Resumo.Hmac.Iguais(Resumo.Hmac.Sha256(segredo, m), a),
            ate: 128);

        Console.WriteLine(tentativa is null
            ? "  não passa em nenhum dos 128 tamanhos testados."
            : $"  PASSOU com tamanho {tentativa} -- isto seria grave.");

        return 0;
    }

    private const string Ajuda = """
        resumo -- SHA-2 e HMAC do zero

          resumo resumir [TEXTO]        as seis funções sobre um texto
          resumo arquivo ARQUIVO        as seis funções sobre um arquivo
          resumo hmac    CHAVE MENSAGEM os três HMAC
          resumo ataque                 o ataque de extensão, acontecendo

        Sem TEXTO, o `resumir` lê a entrada padrão.
        """;
}
