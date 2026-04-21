# appletree

Three.js application that renders a stylized 3D apple tree.

## Local development

```bash
npm install
npm run dev
```

The app is served on `http://localhost:3333`.

## Production build

```bash
npm run build
npm run preview
```

## Docker Compose

```bash
docker compose up --build
```

The container serves the built static site on port `3333`, which is a better fit for Dokploy or another Docker-based VPS workflow.

## Dokploy / GitHub

This repo is ready to push to GitHub and deploy from a Docker-aware platform.

For Dokploy:

```bash
docker compose up --build -d
```

Use the repository root as the build context and expose port `3333` on the service. Since the app is a static site served by Nginx, no database or persistent volume is required.
