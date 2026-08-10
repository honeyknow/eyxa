# Eyxa EDR - Root Directory Documentation

This file documents the root-level files that orchestrate the Docker containerization, deployment, and repository management for the Eyxa EDR project.

---

## 1. `docker-compose.yml`
- **File Name:** `docker-compose.yml`
- **Location:** `./docker-compose.yml`
- **Purpose:** Orchestrates the multi-container deployment architecture.
- **Simple Explanation:** It's the master switch that turns on both our main application and the secure tunnel that connects it to the internet.
- **Code Explanation:** Defines two services. The `eyxa` service builds from the local `Dockerfile`, maps port 8443, and mounts a persistent volume for the SQLite database. The `cloudflared` service pulls the latest Cloudflare image and runs a tunnel command pointing to the `eyxa` service.
- **Technical Explanation:** Implements a sidecar-like pattern for ingress via Cloudflare Quick Tunnels, effectively bypassing NAT and firewall restrictions on the host machine without exposing local ports directly to the public internet. Uses named Docker volumes (`eyxa_db:/app/backend/db`) to ensure data persistence across ephemeral container lifecycles.
- **Relation with Other Files:** Triggers the build of `Dockerfile`. Launched by `start.sh`.
- **Known Issues:** Issue 1

## 2. `Dockerfile`
- **File Name:** `Dockerfile`
- **Location:** `./Dockerfile`
- **Purpose:** Defines the multi-stage build for the Eyxa application.
- **Simple Explanation:** It's the recipe that tells Docker how to build our app, taking the frontend and backend code and packaging them together into a single, runnable box.
- **Code Explanation:** Uses a multi-stage process. Stage 1 uses a `node:20` image to install dependencies and run the Vite build. Stage 2 uses a `python:3.11` image, copies the compiled frontend assets from Stage 1 into the backend's static folder, installs Python pip packages, and sets up `uvicorn` to serve the API and frontend together.
- **Technical Explanation:** Implements an optimized CI/CD-style build directly within Docker. By leveraging Vite's `outDir` configuration, the Node builder stage directly deposits the compiled Single-Page Application (SPA) into the Python backend's expected static directory structure. The runtime stage minimizes attack surface and image size by completely discarding the Node toolchain.
- **Relation with Other Files:** Consumes code from `dashboard/` and `backend/`. Its context is filtered by `.dockerignore`. Called by `docker-compose.yml`.
- **Known Issues:** Issue 2, Issue 3

## 3. `start.sh`
- **File Name:** `start.sh`
- **Location:** `./start.sh`
- **Purpose:** Automates deployment and tunnel URL retrieval.
- **Simple Explanation:** A quick-start script you run to launch the whole app and get the dynamic internet link required to access the dashboard or configure agents.
- **Code Explanation:** Executes `docker-compose up -d --build` to start the containers in the background. It then loops for up to 30 seconds, parsing the `eyxa-tunnel` logs to extract the dynamically assigned Cloudflare URL using `grep` and `tail`, printing the final URL to the console.
- **Technical Explanation:** Abstracts away the operational complexity of identifying ephemeral Cloudflare endpoints. Uses standard POSIX Bash constructs to poll and parse standard output streams from the Docker daemon.
- **Relation with Other Files:** Executes `docker-compose.yml` and reads logs from its created containers.
- **Known Issues:** Issue 4

## 4. `docker-commands.txt`
- **File Name:** `docker-commands.txt`
- **Location:** `./docker-commands.txt`
- **Purpose:** Reference guide for developers and administrators.
- **Simple Explanation:** A cheat sheet of useful commands to restart the app, view logs, or delete the database when troubleshooting.
- **Code Explanation:** Contains raw Bash, Docker, and SQLite commands categorized by use case (e.g., Troubleshooting, Database Commands).
- **Technical Explanation:** Provides immediate access to administrative operations without requiring the user to memorize Docker or SQLite syntaxes, including dropping into the `sqlite3` interactive shell directly inside the container namespace.
- **Relation with Other Files:** Documents how to interact with `docker-compose.yml`, `start.sh`, and the resulting containers.
- **Known Issues:** Issue 5

## 5. `.dockerignore`
- **File Name:** `.dockerignore`
- **Location:** `./.dockerignore`
- **Purpose:** Optimizes the Docker build context.
- **Simple Explanation:** Tells Docker which files to ignore when building the app so the build finishes faster.
- **Code Explanation:** Lists directories like `node_modules`, `__pycache__`, local databases (`eyxa.db`), and garbage folders that should not be sent to the Docker daemon.
- **Technical Explanation:** Reduces the build context size, minimizing I/O overhead and preventing host-specific state (like local SQLite databases or compiled object files) from bleeding into the hermetic container environment.
- **Relation with Other Files:** Works intimately with `Dockerfile` to govern what the `COPY` commands are allowed to see.
- **Known Issues:** None

## 6. `.gitignore`
- **File Name:** `.gitignore`
- **Location:** `./.gitignore`
- **Purpose:** Protects the Git repository from ephemeral and sensitive data.
- **Simple Explanation:** Tells Git not to upload temporary files, databases, or compiled code to GitHub.
- **Code Explanation:** Contains wildcard rules for Python caches, Javascript modules, compiled binaries (`*.exe`, `*.obj`), IDE configs, and explicitly ignores the `garbage/` directories.
- **Technical Explanation:** Maintains source control hygiene. By explicitly ignoring `*.db*`, it prevents live EDR telemetry from being pushed to public or remote repositories, mitigating a major data exfiltration risk.
- **Relation with Other Files:** Applies universally to the whole repository. Documents why `installer/` is kept intact.
- **Known Issues:** None
