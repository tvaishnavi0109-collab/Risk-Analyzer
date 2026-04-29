# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.

## Artifacts

### `phishguard` (web)

PhishGuard – Multi-Vector Phishing Detection System. A client-side React + TypeScript + Vite app served at `/`. Three scanners (Website, Message, Email) detect common phishing signals using local heuristics — no backend, no network calls.

- **Routing**: `wouter` with `base={import.meta.env.BASE_URL}` — routes: `/`, `/website`, `/message`, `/email`.
- **Styling**: Tailwind v4 (`@tailwindcss/vite`), dark blue/purple gradient theme, Inter font.
- **Folder layout**:
  - `src/pages/` — `Home`, `Website`, `Message`, `Email`, `not-found`
  - `src/components/ui/` — reusable primitives: `Button`, `Card`, `Input` (+ `Textarea`), `Badge`
  - `src/components/` — shared composites: `Navbar`, `Disclaimer`, `ResultPanel`
  - `src/utils/` — detection logic: `scoring` (shared types, risk levels Low/Medium/High at thresholds 40/70), `website`, `message`, `email`
- **Scoring model**: each scanner returns `{ score, level, reasons[] }`. Website also returns `domain`; Message returns matched phrases (highlighted in preview); Email returns `warnings[]`.
