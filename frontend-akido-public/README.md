# FixOps Public Akido Experience

This Vite + React application delivers a fully public version of the FixOps Akido Security portal. It mirrors the authenticated experience so prospects can explore every capability — Command Center, Pipeline integration, Executive briefing, Architecture intelligence, and deployment documentation — without logging in.

## Features

- ✨ **Security Command Center** with simulated telemetry, upload workflows, and real-time activity stream
- ⚙️ **DevOps Pipeline view** showcasing SSDLC stages, CI/CD integrations, and CLI playbooks
- 📊 **Executive briefing** summarizing risk posture, compliance, and threat intelligence
- 🏛️ **Architecture intelligence** describing Bayesian, Markov, and multi-LLM consensus internals
- 🚀 **Installation & Architecture docs** rendered from rich Markdown with download support
- 🌙 **Mode toggle simulation** and persistent FixOps navigation shell for a true product tour

## Getting Started

```bash
cd frontend-akido-public
npm install
npm run dev
```

The development server listens on port **4173**. Run `npm run build` to generate optimized assets.

## Project Structure

```
src/
  components/       # Shared layout and chrome
  pages/            # Route-aligned Akido experiences
  content/          # Markdown sources for docs
```

All telemetry is simulated locally to ensure the UI matches the production experience without backend connectivity.
