# Cookie SameSite Checker

Analiza el atributo `SameSite` de cookies en múltiples dominios. Detecta configuraciones incorrectas que pueden facilitar CSRF, XSS y timing attacks.

**Demo:** https://juguitos.github.io/cookies-same-site-checker

---

## Uso

Ingresa dominios separados por coma o por línea, o sube un `.txt`. Filtra por nivel de riesgo. Exporta a CSV.

El frontend es estático (GitHub Pages). Necesita un backend que haga las peticiones reales, ya que los navegadores no exponen cabeceras `Set-Cookie` a JavaScript por restricciones de seguridad.

---

## Setup

### Opción A — Cloudflare Worker (recomendado para GitHub Pages)

**Vía Wrangler (más fácil):**

```bash
npx wrangler login
npx wrangler deploy
```

Copia la URL `*.workers.dev` que imprime y pégala en **⚙ API** del frontend.

**Vía dashboard (manual):**

1. [workers.cloudflare.com](https://workers.cloudflare.com) → Workers & Pages → Create → **Create Worker**
2. Haz clic en **Edit Code** (editor inline — NO uses el botón Upload/deploy)
3. Borra el código de ejemplo, pega el contenido de `worker.js`, → **Save & Deploy**
4. Copia la URL `*.workers.dev` → pégala en **⚙ API** del frontend

### Opción B — Backend local (Python)

```bash
pip install -r requirements.txt
python api.py
# Backend en http://localhost:5000
```

Luego abre `index.html` **localmente** (no desde GitHub Pages, ya que HTTPS→HTTP está bloqueado por mixed content).

```bash
# Sirve el frontend localmente
python -m http.server 8080
# Abre http://localhost:8080
```

El frontend detecta `localhost:5000` por defecto; no necesitas configurar nada si usas la Opción B localmente.

### Opción C — CLI (original, sin navegador)

```bash
python cookies-cli.py dominios.txt
```

---

## Niveles de riesgo

| Riesgo | Condición |
|--------|-----------|
| **ALTO** | Sin `SameSite` · `SameSite=None` sin `Secure` · cookie sensible sin `HttpOnly` |
| **MEDIO** | `SameSite=None` con `Secure` · cookie sensible sin `HttpOnly` |
| **INFORMATIVO** | `SameSite=Lax` o `Strict` correctamente configurado |

Tokens considerados sensibles: `session`, `auth`, `token`, `sid`, `sess`, `jwt`, `login`.
