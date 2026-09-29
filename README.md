# resumo

A família SHA-2 do zero em C# e .NET 8 — SHA-224, SHA-256, SHA-384, SHA-512,
SHA-512/224, SHA-512/256 e HMAC.

```
$ dotnet resumo.dll resumir abc
  sha-224       23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
  sha-256       ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  sha-384       cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed...
  sha-512       ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a...
  sha-512/224   4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
  sha-512/256   53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
```

## Os juízes

**O `System.Security.Cryptography` do .NET**, que tem uma qualidade rara para um
juiz: além de ser uma implementação madura, é **validada pelo programa CMVP do
NIST** — passou pelos vetores oficiais num laboratório credenciado. Comparar com
ela é comparar com o padrão, indiretamente.

**Os vetores impressos na FIPS 180-4**, para o SHA-224, que o .NET não
implementa, e para o milhão de letras `a`.

| o que se compara | quantos |
|---|---|
| mensagens sorteadas, nas quatro funções | **100.000** |
| HMAC-SHA-256/384/512 com chaves de todos os tamanhos | **20.000** |
| resumos em pedaços contra resumos de uma vez | 5.000 |
| tamanhos escolhidos para quebrar o enchimento | 27 × 2 |

E o que se prova é o que mais importa: uma função de resumo com defeito **não
estoura**. Ela devolve 32 bytes que parecem perfeitamente aleatórios e não são o
resumo de nada — e passam por qualquer conferência a olho. Só a comparação com
outra implementação pega.

## As 152 constantes, recalculadas

As constantes do SHA-2 não saem do nada, e é deliberado: são a parte fracionária
de raízes de primos pequenos. Isso tem nome — ***nothing-up-my-sleeve
numbers***, números de quem não tem nada na manga — e existe para que qualquer
pessoa possa recalculá-las e ver que ninguém escolheu valores com uma fraqueza
escondida dentro.

A preocupação não é paranoia. Em 1975 a NSA mexeu nas caixas de substituição do
DES sem explicar por quê, e o mundo passou vinte anos desconfiando. Em 1994
descobriu-se que as mudanças o **fortaleciam** contra um ataque que ainda era
segredo — e a lição que ficou foi outra: uma constante inexplicada, mesmo boa,
custa vinte anos de confiança.

Este projeto faz o que a explicação promete. Ele **recalcula** as 152, com
aritmética inteira exata — um `double` tem 52 bits de mantissa e são precisos 64:

| constantes | de onde vêm |
|---|---|
| estado do SHA-256 | raízes **quadradas** dos 8 primeiros primos |
| as 64 do SHA-256 | raízes **cúbicas** dos 64 primeiros primos |
| estado do SHA-512 | os mesmos 8 primos, com 64 bits |
| as 80 do SHA-512 | raízes cúbicas dos 80 primeiros primos |
| estado do SHA-384 | raízes quadradas do **9º ao 16º** primo |
| estado do SHA-224 | os 32 bits do **meio** dos mesmos |
| estado do SHA-512/256 | um procedimento da própria FIPS, refeito no teste |

O SHA-224 é o mais estranho: ele pega os bits 32 a 63 da fração, e não os 32 de
cima — porque os de cima já estão no SHA-384. E o SHA-512/256 não sai de primos:
sai de rodar o SHA-512 com o estado inicial **invertido bit a bit** sobre o texto
`"SHA-512/256"`. O teste refaz o procedimento em vez de confiar na tabela.

**Por que SHA-224 e SHA-384 não são simplesmente o SHA-256 e o SHA-512
cortados?** Porque aí o resumo curto seria um prefixo do longo, e quem tivesse um
saberia metade do outro. O estado inicial diferente separa completamente as
funções — é barato e resolve.

## O ataque que este projeto demonstra

```
$ dotnet resumo.dll ataque

O servidor assina assim:  SHA256(segredo || mensagem)

  segredo    (só o servidor sabe, 24 bytes)
  mensagem   usuario=joao&admin=nao
  assinatura 827c1bef18ca37ef0638267259d747d7fc0396b881c001c4dea3629b18c4a07f

O atacante vê só a mensagem e a assinatura. Ele quer
acrescentar "&admin=sim" e não sabe o segredo.

  tamanho do segredo descoberto em 24 tentativas

  mensagem forjada:
    usuario=joao&admin=nao\x80\x00...\x01p&admin=sim

  assinatura forjada: 58b3b8c7cc0b40ae35449aabfeb8141000a3f836bbf43775257a71c82fa468ba
  o servidor calcula: 58b3b8c7cc0b40ae35449aabfeb8141000a3f836bbf43775257a71c82fa468ba

  ACEITA. E o segredo nunca foi descoberto.

Com HMAC, o mesmo ataque:

  não passa em nenhum dos 128 tamanhos testados.
```

`assinatura = SHA256(segredo || mensagem)` **parece** seguro: quem não sabe o
segredo não calcula a assinatura. E é falso.

O motivo está na construção de Merkle–Damgård: **o resumo é o estado interno da
função no fim da mensagem**. Quem o tem, tem o estado — e continua a partir dele
como se nada tivesse acontecido. O único dado que falta é o *tamanho* do segredo,
e são 64 tentativas.

Isso não é teórico: em 2009 a API do Flickr foi quebrada assim, e o padrão
`hash(chave + dados)` ainda aparece em código novo.

**O HMAC existe exatamente por causa disto.** Ele resume duas vezes, com a chave
misturada de dois jeitos diferentes, e a segunda passada quebra a cadeia: o
resultado não é o estado interno de nada que o atacante possa continuar. Há um
teste que tenta o ataque contra o HMAC com os 128 tamanhos de segredo possíveis
e mostra que ele não anda.

**E o SHA-512/256 também é imune**, por outro motivo: o resumo publicado tem 256
bits e o estado interno tem 512. Metade do estado fica de fora, e sem ela não há
de onde continuar. É a mesma ideia que o SHA-3 levou ao limite — e é por isso
que o SHA-3 não precisa de HMAC, basta pôr a chave na frente.

## O enchimento, que é onde se erra

```
mensagem || 0x80 || zeros || comprimento em BITS (big-endian)
```

Três partes, cada uma com um motivo:

**O bit 1 obrigatório** entra sempre, mesmo quando a mensagem já é múltipla do
bloco — e é por isso que uma mensagem de exatamente 64 bytes gera **dois**
blocos. Sem ele, `"abc"` e `"abc\0"` poderiam colidir.

**O comprimento no fim** é o que o Merkle–Damgård chama de *strengthening*, e
impede uma classe inteira de colisões: mensagens de tamanhos diferentes têm
entradas diferentes no último bloco, sempre.

**E é esse mesmo campo que torna o ataque possível.** Quem conhece o resumo e o
tamanho sabe exatamente que enchimento foi usado. A mesma decisão que fecha uma
porta abre a outra.

O caso que mais pega implementação caseira é o enchimento que **não cabe** e
atravessa para o bloco seguinte — o que acontece para toda mensagem cujo resto
está entre 56 e 63 bytes. Há um teste com 27 tamanhos escolhidos exatamente para
isso.

## O efeito avalanche, medido

Uma função de resumo promete que trocar **um bit** da entrada muda metade dos
bits da saída. Dá para medir: duas mil mensagens, um bit trocado em cada, e a
média de bits que mudaram nos 256 da saída.

O teste exige entre 122 e 134 — o desvio padrão de 256 moedas é 8, então 128 ± 6
é confortável para duas mil amostras.

## O SHA-512 é mais rápido que o SHA-256

Em máquinas de 64 bits, e mesmo produzindo o dobro de saída. Ele processa 128
bytes por 80 rodadas contra 64 bytes por 64 rodadas — **1,6 byte por rodada
contra 1,0** —, e cada rodada custa o mesmo num processador que soma 64 bits de
uma vez.

É por isso que o SHA-512/256 existe: dá a mesma segurança do SHA-256, mais
rápido, e de quebra imune ao ataque de extensão.

## Os comandos

```
resumo resumir [TEXTO]        as seis funções sobre um texto
resumo arquivo ARQUIVO        as seis funções sobre um arquivo
resumo hmac    CHAVE MENSAGEM os três HMAC
resumo ataque                 o ataque de extensão, acontecendo
```

## A comparação em tempo constante

`Hmac.Iguais` percorre os dois vetores inteiros sempre. Um `==` comum para no
primeiro byte diferente, e esse "para" é mensurável: um atacante que meça o tempo
de resposta descobre a assinatura **um byte de cada vez** — 256 tentativas por
byte, 32 bytes, oito mil tentativas, em vez das 2²⁵⁶ que a criptografia
prometia.

Não é teórico: é o ataque de Nate Lawson contra o Google Keyczar, em 2009, feito
pela rede.

## Rodar

.NET 8. Zero dependências fora do xUnit, e só nos testes.

```
dotnet test testes/Resumo.Testes/Resumo.Testes.csproj -c Release
dotnet run --project ferramentas/Cli/Cli.csproj -- ataque
```

## Não use isto

Sério. Use o `System.Security.Cryptography`, que é validado, tem caminhos em
instrução de processador (`SHA256` tem instrução dedicada em x86 desde 2013 e em
ARM desde o ARMv8) e é auditado por gente que faz isso profissionalmente.

Este projeto existe para **entender** — e a parte que ele entende melhor é por
que a construção ingênua que todo mundo escreve na primeira vez não serve.

## O que ele não faz

Não tem SHA-1 nem MD5, que estão quebrados para colisão e não deviam ser
escritos de novo. Não tem SHA-3, que é uma construção completamente diferente
(esponja, em vez de Merkle–Damgård) e merece um projeto próprio. Não tem HKDF,
PBKDF2 nem nada de derivação de chave. E não é rápido: não usa as instruções
dedicadas do processador, então perde por uma ordem de grandeza para o .NET em
mensagens grandes.

## Licença

MIT.
