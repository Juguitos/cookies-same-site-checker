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

1. Ve a [workers.cloudflare.com](https://workers.cloudflare.com) → Create Worker
2. Pega el contenido de `worker.js`
3. Deploy → copia la URL `*.workers.dev`
4. En el frontend, haz clic en **⚙ API** y pega esa URL

O con Wrangler CLI:

```bash
npx wrangler deploy worker.js --name cookie-checker
```

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
