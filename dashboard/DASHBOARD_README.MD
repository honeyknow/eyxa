# Eyxa Dashboard Architecture & Code Audit

This document contains a file-by-file breakdown of the `dashboard/` frontend React application for the Eyxa platform, detailing its architecture, purpose, and tracking any security issues found during the audit.

---

### 1. `src/main.tsx`
- **File Name:** `main.tsx`
- **Location:** `./src/main.tsx`
- **Purpose:** Application entry point.
- **Simple Explanation:** This is the absolute starting point for the React dashboard frontend. It hooks the React app into the standard HTML `<div id="root">` element.
- **Code Explanation:** It wraps the core `<App />` component in global providers: `<BrowserRouter>` for URL routing, `<ToastProvider>` for global alert popups, and `<DashboardProvider>` for maintaining global UI state.
- **Technical Explanation:** StrictMode is enabled to catch legacy lifecycle issues.
- **Relation with Other Files:** Imports `App.tsx` and context providers.
- **Known Issues:** None.

### 2. `src/App.tsx`
- **File Name:** `App.tsx`
- **Location:** `./src/App.tsx`
- **Purpose:** Core layout and client-side routing.
- **Simple Explanation:** This file decides which page to show based on the URL (e.g., `/rules` shows the Rules Engine). It also checks if you are logged in before showing anything.
- **Code Explanation:** Uses `react-router-dom` to map URL paths to React components (`<Overview>`, `<ThreatHunt>`, etc.). On mount, it calls `api.getMe()` to verify the user's session token.
- **Technical Explanation:** Implements route guards. If a user is not authenticated, they are forced to `<Navigate to="/login" replace />`. It also restricts access to the `<AdminPanel>` component based on the `user.role === 'admin'` check.
- **Relation with Other Files:** Imports all page components from `src/pages/`.
- **Known Issues:** None. Client-side role checks are backed by server-side verification.

### 3. `src/api/client.ts`
- **File Name:** `client.ts`
- **Location:** `./src/api/client.ts`
- **Purpose:** API client and TypeScript definitions.
- **Simple Explanation:** This file holds the phone book for talking to the backend server. Whenever the dashboard wants to fetch alerts, trigger commands, or log in, it uses the functions defined here.
- **Code Explanation:** Wraps `axios` with `withCredentials: true` to automatically pass the JWT HttpOnly cookie to the backend. Includes an interceptor that automatically redirects the user to the `/login` page if any API request returns a 401 Unauthorized status.
- **Technical Explanation:** It holds all the strict TypeScript interfaces (`Alert`, `LiveStats`, `SigmaRule`, etc.) that map 1-to-1 with the backend SQLite database schemas.
- **Relation with Other Files:** Used by almost every React component in the application to perform data fetching.
- **Known Issues:** None.

---
## Components (`src/components/`)

### 4. `src/components/AccountMenu.tsx`
- **File Name:** `AccountMenu.tsx`
- **Location:** `./src/components/AccountMenu.tsx`
- **Purpose:** User dropdown menu in the Topbar.
- **Simple Explanation:** This is the little menu in the top right corner where you can click your name to sign out or delete your account.
- **Code Explanation:** Uses React hooks (`useState`, `useRef`, `useEffect`) to build a custom dropdown that closes when you click outside of it. It requires a two-step confirmation to delete an account to prevent accidental clicks.
- **Technical Explanation:** Standard functional React component with inline CSS styling and Lucide-react icons.
- **Relation with Other Files:** Rendered by `Topbar.tsx`. Calls `api.logout()` and `api.deleteMyData()`.
- **Known Issues:** None.

### 5. `src/components/AgentInstallModal.tsx`
- **File Name:** `AgentInstallModal.tsx`
- **Location:** `./src/components/AgentInstallModal.tsx`
- **Purpose:** Modal displaying agent installation instructions.
- **Simple Explanation:** When you click "Add Endpoint", this popup appears showing you your secret enrollment token, the URL of the server, and the exact commands to run to download and install the agent on a Windows PC without Windows Defender blocking it.
- **Code Explanation:** Uses simple React state to manage visibility. Dynamically parses the browser's `window.location.origin` to automatically figure out the correct backend URL to show the user. Includes standard copy-to-clipboard functionality.
- **Technical Explanation:** Purely presentational. It provides a direct static download link to `/eyxa-agent.zip`.
- **Relation with Other Files:** Rendered by `Overview.tsx` or `AdminPanel.tsx`.
- **Known Issues:** None.

### 6. `src/components/AlertQueue.tsx`
- **File Name:** `AlertQueue.tsx`
- **Location:** `./src/components/AlertQueue.tsx`
- **Purpose:** Live sidebar showing the queue of security alerts.
- **Simple Explanation:** This is the scrolling list on the left side of the Threat Hunt page. It shows all the alerts that need to be investigated. You can use your keyboard to quickly go through them, mark them as investigated, or add tags like `#falsepositive`.
- **Code Explanation:** Uses a custom `usePolling` hook to fetch new alerts every 5 seconds. Implements a global `keydown` event listener to add vim-like shortcuts (`j`/`k` to navigate, `i` to investigate).
- **Technical Explanation:** It manages complex optimistic UI updates (e.g., locking a button with a spinner while an alert is being tagged via `actionIds` Set). It does not use `localStorage`; all tags and states are completely backed by the server.
- **Relation with Other Files:** Rendered by `ThreatHunt.tsx`. Fetches data from `api.getAlerts()`.
- **Known Issues:** None.

### 7. `src/components/BlastRadius.tsx`
- **File Name:** `BlastRadius.tsx`
- **Location:** `./src/components/BlastRadius.tsx`
- **Purpose:** Visual graph showing the full impact of a compromised process.
- **Simple Explanation:** When an alert fires, this component draws a web diagram. In the center is the malicious process, and circling it are all the files it touched, registry keys it changed, and IP addresses it talked to.
- **Code Explanation:** Uses the `@xyflow/react` library. It calculates a custom `radialLayout` (using basic trigonometry) to perfectly space out all the related events in a circle around the root node.
- **Technical Explanation:** When a user clicks a node in the graph, it renders a detailed side panel showing the raw JSON fields of that specific event.
- **Relation with Other Files:** Calls `api.getPivotEvents(rootGuid, 'all')` to fetch the data.
- **Known Issues:** None.

### 8. `src/components/CommandConsole.tsx`
- **File Name:** `CommandConsole.tsx`
- **Location:** `./src/components/CommandConsole.tsx`
- **Purpose:** Live response terminal interface for interacting with endpoints.
- **Simple Explanation:** This is the black terminal window at the bottom of the Endpoint Details page. It lets the analyst type PowerShell commands and see the exact output returned by the agent.
- **Code Explanation:** It uses a `setInterval` loop to constantly poll `api.getCommands(agentId)` every 3 seconds. When you send a command, it pushes it to the backend queue. The component carefully manages scrolling, staying at the bottom automatically unless you scroll up to read past output.
- **Technical Explanation:** The C agent sends stdout back to the server in Base64 encoding to prevent JSON escaping issues. This component decodes it locally via JavaScript's `atob()` function before rendering.
- **Relation with Other Files:** Displayed on the `EndpointDetails.tsx` page.
- **Known Issues:** The backend currently freezes for 30 seconds if a command produces massive output (known architecture flaw documented in the server rules).

### 9. `src/components/EvidenceDrawer.tsx`
- **File Name:** `EvidenceDrawer.tsx`
- **Location:** `./src/components/EvidenceDrawer.tsx`
- **Purpose:** Sidebar that displays exact evidence for an alert.
- **Simple Explanation:** When you click an alert in the queue, this panel slides open on the right to show you the exact command line, file path, or registry key that caused the alert to fire.
- **Code Explanation:** It calls `api.getAlertEvidence(alert_id)` and loops over the returned `artifacts` object, rendering sections for `process`, `network`, `registry`, and `file`.
- **Technical Explanation:** It includes a "Generic dynamic fallback" block at the bottom that will safely render unknown JSON keys if the backend sends an artifact type it hasn't hardcoded CSS for.
- **Relation with Other Files:** Driven by the backend `/alerts/{id}/evidence` endpoint.
- **Known Issues:** None.

### 10. `src/components/AIAssistant.tsx`
- **File Name:** `AIAssistant.tsx`
- **Location:** `./src/components/AIAssistant.tsx`
- **Purpose:** UI for configuring and triggering the Groq LLM integration.
- **Simple Explanation:** This is the panel that lets you ask the AI to summarize an alert. It also has a settings page where you can paste your Groq API key and configure exactly how the backend shrinks down logs before sending them to the AI.
- **Code Explanation:** Manages the API key state, the YAML schema state, and the generated markdown report. When "Analyze" is clicked, it blocks the UI with a spinner until the backend finishes talking to Groq.
- **Technical Explanation:** It uses `ReactMarkdown` to safely render the AI's markdown response without exposing the dashboard to Cross-Site Scripting (XSS) vulnerabilities.
- **Relation with Other Files:** Hits `ai_api.py` endpoints. Rendered as a tab in `EndpointDetails.tsx` and `ThreatHunt.tsx`.
- **Known Issues:** None.

### 11. `src/components/ProcessTree.tsx`
- **File Name:** `ProcessTree.tsx`
- **Location:** `./src/components/ProcessTree.tsx`
- **Purpose:** Hierarchical graph of process execution.
- **Simple Explanation:** Shows the "family tree" of a compromised process. You can see exactly which program launched the malware, and what child programs the malware spawned.
- **Code Explanation:** Uses the `dagre` library to mathematically calculate the layout of a Directed Acyclic Graph (DAG) so lines don't cross in a messy way. The actual drawing is handed off to `@xyflow/react`.
- **Technical Explanation:** Clicking a node updates the selected state and slides open a details panel showing the exact PID, user, and command line for that specific point in the tree.
- **Relation with Other Files:** Fetches from `api.getProcessTree()`.
- **Known Issues:** None.

### 12. `src/components/Topbar.tsx`
- **File Name:** `Topbar.tsx`
- **Location:** `./src/components/Topbar.tsx`
- **Purpose:** Global navigation header.
- **Simple Explanation:** The persistent black bar at the top of every screen. It contains the logo, navigation links (Overview, Threat Hunt, etc.), the global health indicator, and the Download button.
- **Code Explanation:** Uses `useLocation` to determine which tab is active and renders an underline. Conditionally renders the "Admin" tab only if `isAdmin` is true. Pulls real-time stats from the `useDashboard()` context.
- **Technical Explanation:** Standard layout component.
- **Relation with Other Files:** Renders `AccountMenu.tsx` and `AgentInstallModal.tsx`.
- **Known Issues:** None.

### 13. Miscellaneous UI Components
- **Files:** `Button.tsx`, `CopyButton.tsx`, `ErrorBoundary.tsx`
- **Purpose:** Reusable UI primitives.
- **Simple Explanation:** Standard building blocks (a styled button, a button that copies text to your clipboard, and a wrapper that prevents the app from crashing if a child component fails).
- **Known Issues:** None.

---
## Contexts (`src/context/`)

### 14. `src/context/DashboardContext.tsx`
- **File Name:** `DashboardContext.tsx`
- **Location:** `./src/context/DashboardContext.tsx`
- **Purpose:** Global state management for dashboard stats and system health.
- **Simple Explanation:** Instead of every page constantly asking the backend for stats, this file acts as a central brain. It asks the backend for stats every 10 seconds and shares that information with the rest of the app. It also plays a notification beep and updates the browser tab title when a new alert fires.
- **Code Explanation:** Uses React Context and the `usePolling` hook to fetch data.
- **Technical Explanation:** Minimizes redundant network requests and centralizes the `api.getStats()` and `api.getHealth()` calls.
- **Relation with Other Files:** Consumed heavily by `Topbar.tsx` and `Overview.tsx`.
- **Known Issues:** None.

### 15. `src/context/ToastContext.tsx`
- **File Name:** `ToastContext.tsx`
- **Location:** `./src/context/ToastContext.tsx`
- **Purpose:** Global toast notification system.
- **Simple Explanation:** Provides the popup notifications (e.g., "Copied to clipboard") that appear at the top of the screen.
- **Code Explanation:** Uses React `createPortal` to render toasts at the root of the HTML document so they overlay properly on all pages.
- **Technical Explanation:** Simple message queue with automatic 4-second dismissal.
- **Relation with Other Files:** Used universally.
- **Known Issues:** None.

---
## Hooks (`src/hooks/`)

### 16. `src/hooks/usePolling.ts`
- **File Name:** `usePolling.ts`
- **Location:** `./src/hooks/usePolling.ts`
- **Purpose:** Custom React hook for auto-refreshing data.
- **Simple Explanation:** This is the engine that keeps the dashboard live without needing to hit "refresh". It asks the server for new data every X seconds.
- **Code Explanation:** It uses the `setInterval` API mixed with the browser's `Page Visibility API`. If you switch to another browser tab, it stops polling to save network bandwidth and server CPU. When you come back, it instantly fires a fresh request.
- **Technical Explanation:** Safely handles React component unmounting to prevent memory leaks or state updates on unmounted components via a `cancelledRef`.
- **Relation with Other Files:** Used by `AlertQueue.tsx`, `CommandConsole.tsx`, and `DashboardContext.tsx`.
- **Known Issues:** None.

---
## Pages (`src/pages/`)

### 17. `src/pages/AdminPanel.tsx`
- **File Name:** `AdminPanel.tsx`
- **Location:** `./src/pages/AdminPanel.tsx`
- **Purpose:** System administration and deep control plane.
- **Simple Explanation:** A page only visible to admins. It shows system health (CPU, RAM, DB size). It allows admins to create new users, see other users' plaintext passwords (for testing/debug), change their roles, or hard-delete them. It also lets admins manage or delete specific enrolled agents.
- **Code Explanation:** It manually implements a 1-second `setInterval` loop to fetch live server stats. It calls various `api.admin*` endpoints for actions.
- **Technical Explanation:** It manages a lot of loading states concurrently using a dictionary map `activeActions` to prevent button spamming while network requests resolve.
- **Relation with Other Files:** Accessible via `/admin` route. Calls multiple `admin_api.py` endpoints.
- **Known Issues:** None on the frontend, but the backend exposing plaintext passwords is a known architecture flaw documented in the backend audit.

### 18. `src/pages/EndpointDetails.tsx`
- **File Name:** `EndpointDetails.tsx`
- **Location:** `./src/pages/EndpointDetails.tsx`
- **Purpose:** Deep dive into a specific machine/agent.
- **Simple Explanation:** When you click on an agent from the Overview page, it takes you here. It shows you the PC's hardware (RAM, CPU, Hard drives), a live-updating graph of its performance, and the Command Console at the bottom to send it commands.
- **Code Explanation:** It opens a direct WebSocket (`wss://`) connection to the server to get sub-second live performance telemetry for the graphs (rendered using `Recharts`).
- **Technical Explanation:** It manages an array of the last 180 ticks (15 minutes at 5s intervals) to draw the sliding line charts.
- **Relation with Other Files:** Renders `CommandConsole.tsx` at the bottom.
- **Known Issues:** None.

### 19. `src/pages/Firehose.tsx`
- **File Name:** `Firehose.tsx`
- **Location:** `./src/pages/Firehose.tsx`
- **Purpose:** High-performance real-time streaming view of all incoming telemetry.
- **Simple Explanation:** A live stream (like The Matrix) of everything happening on the network. You can filter by host, search for specific files, and instantly download a CSV of the data on screen. 
- **Code Explanation:** It uses `react-virtuoso` for virtualized list rendering (only rendering the rows visible on screen). It builds a custom SVG `Sparkline` graph at the top to show log volume over time.
- **Technical Explanation:** It implements a complex manual "drip-feed" buffer using a queue and `setInterval`. Instead of updating React state with 500 new events at once (which drops frames), it splices 20 events into state every 80ms, producing a buttery-smooth waterfall animation.
- **Relation with Other Files:** Accessible via `/firehose` route. Calls `getTimeline()`.
- **Known Issues:** None.

### 20. `src/pages/Login.tsx`
- **File Name:** `Login.tsx`
- **Location:** `./src/pages/Login.tsx`
- **Purpose:** Standard login screen.
- **Simple Explanation:** The very first screen you see before accessing the dashboard.
- **Code Explanation:** Collects email and password, calls `api.login()`, and upon success immediately calls `api.getMe()` to pull down the authenticated user's role and enrollment token.
- **Technical Explanation:** Purely presentational with local state for loading and errors.
- **Relation with Other Files:** Rendered by `App.tsx` when not logged in.
- **Known Issues:** None.

### 21. `src/pages/Overview.tsx`
- **File Name:** `Overview.tsx`
- **Location:** `./src/pages/Overview.tsx`
- **Purpose:** Main landing dashboard and agent manager.
- **Simple Explanation:** The home page. It shows high-level stats (how many agents are online, total alerts), a list of all enrolled Windows machines, and recent alerts. You can also delete or purge agents from here.
- **Code Explanation:** It uses `useDashboard()` for the top stats, and implements its own `setInterval` to fetch the list of agents and the 4 most recent alerts every 15 seconds.
- **Technical Explanation:** It calculates "Live" status locally by comparing the agent's `last_seen` timestamp to `Date.now()`. If it's within 5 minutes, it shows a green dot.
- **Relation with Other Files:** Hits multiple endpoints like `getHosts()` and `deleteHost()`.
- **Known Issues:** None.

### 22. `src/pages/RulesEngine.tsx`
- **File Name:** `RulesEngine.tsx`
- **Location:** `./src/pages/RulesEngine.tsx`
- **Purpose:** Management interface for Sigma detection rules.
- **Simple Explanation:** This page lets you see all the detection rules loaded into the engine. You can turn them on/off, upload new Sigma `.yml` files, edit existing rules, and see statistics (like which rules are "dead" or producing too much noise). You can also click a button to see exactly what SQL query the engine generates for a specific rule.
- **Code Explanation:** It maintains state for the list of rules, and uses several sub-components like `YamlModal` (for uploading/editing), `StatsPanel` (for the performance metrics), and `SqlModal` (to view the compiled SQL).
- **Technical Explanation:** Forms and modals heavily use React state to track inputs. The SQL Modal calls `api.getRuleSql(id)` to retrieve the compiled `sqlite` string from `pySigma` in the backend.
- **Relation with Other Files:** Interacts with `/api/rules/*` endpoints.
- **Known Issues:** None.

### 23. `src/pages/ThreatHunt.tsx`
- **File Name:** `ThreatHunt.tsx`
- **Location:** `./src/pages/ThreatHunt.tsx`
- **Purpose:** Primary investigation interface for responding to alerts.
- **Simple Explanation:** This is the main workspace for a security analyst. It shows the Alert Queue on the left. When you click an alert, the right side opens up with tabs for Evidence (JSON), Timeline (logs before/after the alert), Process Tree (visual parent/child processes), Blast Radius (a large graph of connected events), and AI Assistant (an AI summary).
- **Code Explanation:** It manages the `activeTab` state and selectively renders the corresponding sub-component (`BlastRadius`, `AIAssistant`, `ProcessTree`, `EvidenceDrawer`).
- **Technical Explanation:** The 'Timeline' tab implements infinite scrolling in both directions (`older` and `newer`). When an alert is selected, it queries the backend for the surrounding context of that specific event and loads it into the `timelineEvents` state array, keeping it strictly sorted by timestamp.
- **Relation with Other Files:** Composes many components from `src/components/`.
- **Known Issues:** None.

---
## API (`src/api/`)

### 24. `src/api/client.ts`
- **File Name:** `client.ts`
- **Location:** `./src/api/client.ts`
- **Purpose:** API client and TypeScript interface definitions.
- **Simple Explanation:** This file holds all the functions the dashboard uses to talk to the backend server (like logging in, getting alerts, or fetching rules). It also defines the "shapes" of the data (like what an `Alert` object looks like).
- **Code Explanation:** It configures `axios` to point to `/api` and automatically sends cookies (`withCredentials: true`). It also exports a giant `api` object containing all the endpoints.
- **Technical Explanation:** It implements an Axios interceptor that listens for `401 Unauthorized` responses. If a session expires and an API call fails with 401, it automatically redirects the user to `/login`.
- **Relation with Other Files:** Imported by almost every other file in the dashboard to make network requests.
- **Known Issues:** None.

---
## Utilities (`src/utils/`)

### 25. `src/utils/severity.ts`
- **File Name:** `severity.ts`
- **Location:** `./src/utils/severity.ts`
- **Purpose:** Centralized logic for severity colors/labels.
- **Simple Explanation:** Ensures "severity_score: 9" is always called "Critical" across the entire app.

### 26. `src/utils/theme.ts`
- **File Name:** `theme.ts`
- **Location:** `./src/utils/theme.ts`
- **Purpose:** Icon and color mapping for events.
- **Simple Explanation:** Defines the hex colors and icons (like a globe for DNS or a shield for AMSI) for all telemetry types. It has a dynamic color generator for unknown telemetry types.

### 27. `src/utils/time.ts`
- **File Name:** `time.ts`
- **Location:** `./src/utils/time.ts`
- **Purpose:** Date formatting helpers.
- **Simple Explanation:** Converts raw timestamps into human readable strings like "20m ago" or "Just now".

---
## Application Root

### 28. `src/App.tsx`
- **File Name:** `App.tsx`
- **Location:** `./src/App.tsx`
- **Purpose:** Main application router and auth wrapper.
- **Simple Explanation:** The skeleton of the app. It checks if you are logged in. If you aren't, it sends you to `/login`. If you are, it draws the `Topbar` and then decides which page to load based on the URL (e.g. `/firehose` loads the Firehose page).
- **Code Explanation:** Uses `react-router-dom` for routing. Performs an initial `api.getMe()` call on mount to establish session state.
- **Relation with Other Files:** Imports all Pages and the Topbar. Wraps pages in `ErrorBoundary`.

### 29. `src/main.tsx`
- **File Name:** `main.tsx`
- **Location:** `./src/main.tsx`
- **Purpose:** React DOM entry point.
- **Simple Explanation:** The very first file that runs in the browser. It attaches the React app to the HTML page.
- **Code Explanation:** Renders `App` wrapped inside `BrowserRouter`, `ToastProvider`, and `DashboardProvider`.

