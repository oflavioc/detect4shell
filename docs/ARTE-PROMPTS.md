# Detect4Shell — kit de prompts de arte + style guide

Prompts prontos para gerar a identidade visual do repo (logo, banner, mascote) em
Midjourney / DALL·E 3 / Flux / Ideogram. Os prompts estão em **inglês** (os modelos rendem
melhor assim); os rótulos e notas em PT-BR. **Tom:** "Segurança Descomplicada" — limpo,
amigável e um pouco divertido, **não** sombrio/ameaçador.

> ⚠️ Mascote **original**, inspirado na *energia* do meme do "gato gritando num monte de A",
> mas um personagem **novo e distinto** (não copiar o gato do vídeo original — direitos de terceiros).

---

## 🎨 Paleta (use estes hex em toda arte)
- Fundo: `#0b0e14` → `#11161f` (quase-preto azulado)
- Parede de "A": `#2a3550` / `#36456a` (azul-acinzentado apagado)
- **Vermelho-alerta (o "=" / o "4"): `#ff5c57`** ← a cor-assinatura
- Verde-menta (escudo / "defensivo / seguro"): `#8fe388`
- Texto claro: `#eef2f8` · Cinza secundário: `#8b98b0`

**Tipografia:** monoespaçada para código/parede-de-A (JetBrains Mono, Fira Code); sans-serif
limpa e amigável para o wordmark (Inter, Satoshi, Montserrat SemiBold).

---

## 1) LOGO / MASCOTE (quadrado — avatar, favicon, ícone)

```
Flat vector mascot logo for an open-source cybersecurity tool called "Detect4Shell".
A cute, slightly chubby original tuxedo cat (black-and-white, green eyes), mouth open in a
tiny confident "aaa" meow, sitting in front of a faint wall of repeating monospace letter "A"
characters. One single bright red "=" sign floats beside the cat as the only pop of color.
The cat holds or stands behind a small minimalist mint-green shield with a check mark
(meaning "defense / detection"). Clean flat design, thick rounded outlines, friendly and
approachable, NOT scary. Dark near-black navy background (#0b0e14). Limited palette:
off-white cat, muted blue-grey "A" wall, alert-red "=" (#ff5c57), mint-green shield (#8fe388).
Centered, balanced, works as a small 64px app icon. Vector, high contrast, no text.
--ar 1:1 --style raw
```
*Dica:* peça variações com/sem o escudo; a versão só-gato+"=" vira um favicon ótimo.

## 2) BANNER SOCIAL DO REPO (1280×640 — GitHub social preview / topo do README)

```
Wide hero banner for an open-source cybersecurity project "Detect4Shell". Left side: bold
clean wordmark "Detect4Shell" in off-white sans-serif, with the "4" highlighted in alert red
(#ff5c57); small tagline under it "Segurança Descomplicada · CVE-2026-114938". Background: a
faint field of repeating monospace letter "A" characters in muted blue-grey, with one row
rendered brighter ending in a single large RED "=" (the exploit trigger) as the focal accent.
Right side: the original chubby tuxedo cat mascot walking, mouth slightly open, next to a small
mint-green shield-with-check icon. Dark near-black navy gradient background (#0b0e14 to #11161f).
Flat vector, modern, friendly, lots of negative space, developer-tool aesthetic. Palette:
off-white text, muted blue-grey, alert red (#ff5c57), mint green (#8fe388).
--ar 2:1 --style raw
```

## 3) FOLHA DE MASCOTE / STICKERS (opcional — comunidade, issues, docs)

```
Sticker sheet of one original tuxedo-cat mascot for a cybersecurity tool, several poses:
(1) meowing at a wall of "A" letters, (2) holding a mint-green shield, (3) pointing at a red
"=" sign, (4) sleeping on a tiny server, (5) giving a thumbs-up paw. Flat vector, thick rounded
outlines, cute and friendly, die-cut sticker style with white border. Palette: off-white cat,
alert red (#ff5c57), mint green (#8fe388), dark navy accents. Transparent background.
--ar 1:1 --style raw
```

## 4) ÍCONE/DIAGRAMA "COMO FUNCIONA" (opcional — para o EXPLICACAO-SIMPLES.md)

```
Simple friendly infographic illustration: a cute cup overflowing with water spilling onto the
table next to it, labeled to represent a memory buffer overflow, with a small "AAAA...=" tag on
the incoming stream. Flat vector, soft rounded shapes, educational children's-book style, calm
and non-threatening. Palette: muted blue-grey, alert red accent (#ff5c57), mint green (#8fe388),
off-white background. No scary imagery.
--ar 16:9 --style raw
```

---

## Regras de consistência (para qualquer arte nova)
- **Sempre** uma única cor quente (vermelho `#ff5c57`) como destaque; o resto frio/neutro.
- O **"="** é o símbolo-assinatura do gatilho — use-o como ponto focal.
- Mascote **sempre amigável** (olhos grandes, traços arredondados). Nada de caveira, cadeado
  "hacker", capuz, matrix-chuva-verde — isso contradiz "Segurança Descomplicada".
- Fundo escuro navy, **não** preto puro. Bordas grossas e arredondadas (flat/vetorial).
- Legível em 64px (logo) e em tema claro E escuro do GitHub.

## Notas por ferramenta
- **Midjourney:** mantenha `--ar` e `--style raw`; adicione `--no text` no logo se aparecer texto indesejado.
- **DALL·E 3 / ChatGPT:** remova os `--flags`, peça "flat vector, transparent/dark background, no gibberish text".
- **Ideogram / Flux:** melhores quando você PRECISA do texto "Detect4Shell" nítido no banner.
- Peça sempre **fundo transparente (PNG)** para o logo e os stickers.
