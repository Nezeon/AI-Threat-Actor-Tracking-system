# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HivePro Threat Intel AI — a Threat Intelligence Platform (TIP) that uses Google Gemini to generate real-time threat actor profiles. It features client-side RAG (upload PDF/CSV reports as trusted context for the AI), granular section refresh, MITRE ATT&CK enrichment, URL validation, and Excel export.

## Commands

```bash
# Install all dependencies (root + client + server)
npm run setup

# Run both client and server concurrently (dev mode)
npm run dev

# Run only the client (Vite on port 3000)
npm run dev:client

# Run only the server (tsx watch on port 3001)
npm run dev:server

# Build client for production
npm run build

# Build server TypeScript
cd server && npm run build
```

## Prerequisites

- **PostgreSQL** running locally with a database named `threatintel`
- **`.env`** file in project root (copy from `.env.example`):
  - `GEMINI_API_KEY` — Google Gemini API key
  - `DATABASE_URL` — PostgreSQL connection string (default: `postgresql://localhost:5432/threatintel`)
  - `PORT` — Server port (default: 3001)
  - `CLIENT_ORIGIN` — CORS origin (default: `http://localhost:3000`)

The server auto-creates all tables on startup via `initializeDatabase()` and seeds initial threat actor data if the DB is empty.

## Architecture

**Monorepo with three packages:**

```
/                   Root — concurrently orchestrates client + server
├── client/         React 19 SPA (Vite, TypeScript, Tailwind CSS)
├── server/         Express API (TypeScript, tsx, PostgreSQL via pg)
└── shared/         Shared TypeScript types (ThreatActor, CVE, ChatMessage, etc.)
```

### Client (`client/`)

- **Vite** dev server on port 3000, proxies `/api` requests to the Express server (see `vite.config.ts`)
- Path alias: `@/` maps to `client/src/`
- `client/src/services/apiService.ts` — single HTTP client wrapping all `/api` endpoints
- Views are toggled via `ViewState` enum: ThreatActors, Chat, LiveFeed, TrustedSources
- No routing library — `App.tsx` switches panels based on state

### Server (`server/`)

- Entry: `server/src/index.ts` — Express app with helmet, cors, morgan
- `server/src/env.ts` — loads `.env` from project root via dotenv (imported first)
- ESM throughout — all local imports use `.js` extensions (TypeScript compiles to ESM)
- Route structure: `routes/` → `controllers/` → `services/` + `models/`

**Key services:**
- `geminiService.ts` — core AI logic. Calls Gemini with Google Search grounding, enforces JSON schemas, runs a 4-step post-generation pipeline (trusted CSV override → MITRE enrichment → URL validation → minimum sources)
- `mitreService.ts` — fetches MITRE ATT&CK enterprise data from GitHub, caches in-memory for 24h, provides alias/first_seen lookups
- `urlValidation.ts` — validates source URLs via HEAD/GET requests, whitelists known-stable URL patterns (MITRE, CISA, NVD, etc.)

**Data layer:**
- `config/database.ts` — PostgreSQL pool, schema creation (CREATE TABLE IF NOT EXISTS), seeding
- `models/db.ts` — all DB queries (actors, CVEs, sources, trusted URLs/files, chat messages)
- `data/trustedData.ts` — hardcoded ground-truth data for specific actors (APT29, Volt Typhoon, etc.) used to override/validate AI output

### Database Schema (PostgreSQL)

Six tables: `threat_actors`, `actor_cves`, `actor_sources`, `trusted_urls`, `trusted_files`, `chat_messages`. Schema is defined inline in `config/database.ts`. No migration tool — tables are created on startup.

### AI Pipeline Flow

1. User requests actor profile → controller calls `geminiService.generateActorProfile()`
2. Gemini called with structured JSON schema + Google Search grounding tool
3. Post-generation pipeline:
   - **Step 1**: Override CVEs/aliases/first_seen with trusted CSV ground truth (`trustedData.ts`)
   - **Step 2**: Enrich with MITRE ATT&CK data (aliases, first_seen, ATT&CK URL)
   - **Step 3**: Validate all source URLs (HEAD requests, 5s timeout)
   - **Step 4**: Ensure minimum sources exist
4. Result saved to PostgreSQL and returned to client

### Shared Types

`shared/types.ts` defines `ThreatActor`, `CVE`, `Source`, `ChatMessage`, `NewsItem`, `ViewState`, `TrustedFile`. Both client and server reference these types (client tsconfig includes `../shared`).

## Important Patterns

- The Gemini model used is `gemini-3-flash-preview` (hardcoded in `geminiService.ts`)
- All Gemini calls use `temperature: 0` for deterministic output
- Server uses ESM modules — TypeScript imports require `.js` extension for local files
- The client has no test framework configured; the server has no test framework configured
- Tailwind CSS is used for styling with a dark/cyber aesthetic (`bg-slate-950`)
