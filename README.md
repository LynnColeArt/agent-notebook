# Agent Notebook

An intentionally simple, agent-friendly PHP + SQLite notebook designed for:

- Markdown-first pages
- Hierarchical document paths (`project/agent-brief/plan.md`)
- Bearer-token protected write/read API
- Basic text + image attachments
- Hidden SQLite database via `.htaccess`

## Quick setup

1. Copy `.env.example` to `.env` and set a strong token:

```bash
cp .env.example .env
```

2. Set `AGENT_NOTEBOOK_TOKEN` in `.env` to a strong value.

3. Point your web root at this folder and ensure PHP + PDO SQLite are enabled.

4. Visit `/` in a browser for a minimal dark UI, or use the API directly.

## Environment

- `AGENT_NOTEBOOK_TOKEN` – required, used for `Authorization: Bearer <token>` / `X-Agent-Token`
- `AGENT_NOTEBOOK_DB` – optional sqlite path (defaults to `storage/agent-notebook.sqlite`)
- `AGENT_NOTEBOOK_MAX_UPLOAD_BYTES` – optional max upload size in bytes (defaults to `8,388,608`)

## API endpoints

- `GET /api/page?path=<path>`
  - returns markdown + rendered HTML + metadata
- `POST /api/page?path=<path>`
  - body: `{ "title": "...", "content": "...", "agent": "..." }`
- `GET /api/children?path=<path>`
  - lists immediate child pages for hierarchy segment
- `POST /api/upload?path=<path>`
  - multipart `file` field for attachments
- `GET /api/attachment?id=<attachment_id>`
  - streams attached file
- `GET /api/agents.md`
  - returns the built-in operational document from DB

## Initial built-in doc

An `agents.md` document is created automatically if missing, to provide bootstrapping guidance for agents.

## Security notes

- `.htaccess` blocks direct DB file access and hides `storage/`
- API calls require bearer token for all `/api/*` routes
- Uploads are MIME-filtered to simple text/image/doc types

## Design intent

- Minimal UI for human operators
- Stable machine-friendly API for agents and automation
- Easy to add adapters / integrate with orchestration systems
