# AEGIS-X

External security assessment for web applications.

## Setup

```bash
npm install
cp .env.example .env
# Set OPENROUTER_API_KEY
npm run dev
```

## App structure

| Route | Purpose |
|-------|---------|
| `/` | Start assessment (URL + optional GitHub) |
| `/runs/:id` | Results |
| `/history` | Past assessments |

Backend: recon → risk → threat → report. Stack fingerprinting and surface probes run before AI agents.
