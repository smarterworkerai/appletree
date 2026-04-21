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
docker compose up -d
```

The Compose file pulls the published GHCR image and serves the static site on port `3333`.

## Dokploy / GitHub

This repo is ready to push to GitHub and deploy from a Docker-aware platform.

For Dokploy:

```bash
docker compose up -d
```

Dokploy can deploy this `docker-compose.yml` directly. By default it pulls `ghcr.io/smarterworkerai/appletree:latest`.

The Compose service only exposes internal port `3333`. Configure the public domain and routing in the Dokploy UI instead of publishing a fixed host port in Compose.

To pin a specific published image version, set `IMAGE_TAG` before deployment, for example:

```bash
IMAGE_TAG=sha-0251f90 docker compose up -d
```

Since the app is a static site served by Nginx, no database or persistent volume is required.
