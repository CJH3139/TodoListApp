# CLAUDE.md

## Commands

- `npm install` — install dependencies
- `npm start` — run the Express server (default port 3000)
- No test suite exists

## Architecture

Single-page todo/task management app. Two source files:

- **`server.js`** (~780 lines) — Express backend with SQLite/Turso database, JWT auth, OAuth, REST API, Telegram bot
- **`todo-app.html`** (~4044 lines) — Self-contained frontend: CSS + HTML + vanilla JS in one file

Database uses `@libsql/client` (Turso-compatible). Falls back to `file:local.db` when no `TURSO_DATABASE_URL` is set. Three tables: `users`, `tasks` (tasks stored as a single JSON blob per user in `task_data`), and `telegram_users` (maps Telegram chat IDs to app user accounts).

## Environment

Copy `.env.example` to `.env`. Required variables:

- `JWT_SECRET` — token signing key
- `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` — database (omit both for local SQLite file)
- `BASE_URL` — deployment URL (used for OAuth redirect URIs)
- `OPENAI_API_KEY` — voice task parsing & Telegram message parsing (calls gpt-4o-mini via OpenAI Responses API)
- `{DISCORD,GITHUB,GOOGLE}_CLIENT_ID` / `_CLIENT_SECRET` — OAuth providers (all optional)
- `TELEGRAM_BOT_TOKEN` — Telegram bot (optional, get from @BotFather)

## Backend API (`server.js`)

All task/auth endpoints are under `/api`:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/register` | No | Create account (username/password) |
| POST | `/api/login` | No | Login, returns JWT |
| GET | `/api/verify` | JWT | Validate token |
| GET | `/api/tasks` | JWT | Fetch user's task blob |
| POST | `/api/tasks` | JWT | Save user's task blob |
| GET | `/api/oauth/:provider` | No | Start OAuth flow |
| GET | `/api/oauth/:provider/callback` | No | OAuth callback |
| POST | `/api/parse-task` | No | Voice-to-task via OpenAI |

Auth middleware: `authenticateToken` extracts Bearer token from `Authorization` header, verifies with `jsonwebtoken`. Tokens expire in 7 days.

## Telegram Bot (`server.js`)

Conditional feature: only starts if `TELEGRAM_BOT_TOKEN` is set. Uses polling mode via `node-telegram-bot-api`.

### Commands

| Command | Behavior |
|---------|----------|
| `/start` | Welcome message with login instructions (or "welcome back" if already linked) |
| `/login <user> <pass>` | Verifies credentials against `users` table, links Telegram chat to app account. Attempts to delete the message for security. |
| `/logout` | Unlinks Telegram chat from app account |
| Any other text | Parses message with OpenAI gpt-4o-mini, creates a task in the user's task blob |

### Key functions

- `initTelegramBot()` — creates bot instance, registers handlers, returns bot or null
- `linkTelegramUser(chatId, username, password)` — authenticates and stores mapping in `telegram_users`
- `getLinkedUser(chatId)` — looks up linked app user by Telegram chat ID
- `unlinkTelegramUser(chatId)` — removes mapping
- `parseTelegramMessage(text)` — calls OpenAI with same JSON schema as `/api/parse-task`
- `createTaskFromTelegram(userId, parsedTask)` — fetches user's task blob, prepends new task, saves back to DB
- `formatTaskConfirmation(task)` — formats Markdown reply for Telegram

Tasks created via Telegram are added to the "general" section and appear immediately in the web app on next sync/load.

## Frontend (`todo-app.html`)

### File layout

| Lines | Content |
|-------|---------|
| 7–1876 | `<style>` — all CSS, themed via CSS custom properties on `:root` / `[data-theme]` |
| 1877–2166 | HTML body — header, nav, modals, task form, calendar, auth forms, about page |
| 2167–4042 | `<script>` — all application JS |

### Key patterns

- **State**: global `state` object (line 2181) holds `tasks[]`, `archivedTasks[]`, `schoolCategories[]`, `ui{}`, `expanded` Set. Persisted to localStorage under key `todo-atlas.v2`.
- **Server sync**: `syncTasksToServer()` is debounced (2s via `syncTimeout`). Called after every `saveState()`. Sends entire task blob as JSON to `POST /api/tasks`.
- **Rendering**: `render()` (line 3166) is the main re-render function. Filters/sorts tasks, builds HTML strings, sets `innerHTML`. `renderCalendar()` handles the calendar view.
- **Sections**: app has "general" and "school" pages. School page has user-created categories with dedicated task lists rendered by `renderSchoolSections()`.
- **Themes**: multiple CSS themes (general, ocean, forest, sunset, midnight, etc.) toggled via `setTheme()` which sets `data-theme` attribute and a CSS variable override.
- **Auth UI**: login/register modal, OAuth buttons. Token stored in localStorage. On load, `handleOAuthCallback()` checks URL params for `auth_token`.
- **Task model**: each task has `id`, `name`, `date`, `priority` (1-5), `tags[]`, `notes`, `done`, `subtasks[]`, `section`, `category`, `recurrence`.

### Major function groups in `<script>`

- **Theme**: `initTheme()`, `setTheme()` (~2273)
- **Calendar**: `renderCalendar()`, `openDayModal()`, `closeDayModal()` (~2335)
- **Auth**: `updateAuthUI()`, `syncTasksToServer()`, `loadState()` (~2517)
- **Voice**: `parseVoiceTask()`, `handleVoiceTranscript()` (~2686)
- **Persistence**: `saveState()`, `loadState()`, `loadStateFromData()` (~2757)
- **Categories**: `renderCategories()`, `addCategory()`, `deleteCategory()`, `setCategory()` (~2996)
- **Rendering**: `render()`, `renderSchoolSections()`, `renderTags()` (~3166)
- **Task CRUD**: `addTask()`, `updateTask()`, `deleteTask()`, `toggleComplete()` (~3447)
- **Subtasks**: `addSubtask()`, `toggleSubtask()`, `deleteSubtask()` (~3537)
- **Init**: `handleOAuthCallback()`, `init()` (~3984)
