#!/usr/bin/env node
import { chromium } from '@playwright/test';

const [url, mode] = process.argv.slice(2);
if (!/^https:\/\/[a-z0-9.-]+$/.test(url || '') || !['fast', 'full'].includes(mode)) {
  throw new Error('browser-e2e-arguments-invalid');
}
const browser = await chromium.launch({ headless: true });
const errors = [];
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  page.on('pageerror', error => errors.push(`page:${error.message}`));
  page.on('console', message => {
    if (message.type() === 'error') errors.push(`console:${message.text()}`);
  });
  page.on('requestfailed', request => errors.push(`request:${request.url()}`));
  const response = await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
  if (!response || !response.ok()) throw new Error('browser-root-response-invalid');
  const canvas = page.locator('#scene');
  await canvas.waitFor({ state: 'visible', timeout: 15000 });
  await page.waitForFunction(() => {
    const element = document.querySelector('#scene');
    const context = element?.getContext('webgl2') || element?.getContext('webgl');
    return Boolean(context && element.width > 100 && element.height > 100);
  }, null, { timeout: 15000 });
  const first = await canvas.boundingBox();
  if (!first || first.width < 100 || first.height < 100) throw new Error('browser-canvas-size-invalid');
  let selected = 1;
  if (mode === 'full') {
    await page.setViewportSize({ width: 800, height: 600 });
    await page.waitForTimeout(250);
    const resized = await canvas.boundingBox();
    if (!resized || resized.width !== 800 || resized.height !== 600) throw new Error('browser-responsive-render-invalid');
    const screenshot = await canvas.screenshot();
    if (screenshot.length < 1000) throw new Error('browser-render-evidence-empty');
    selected = 2;
  }
  if (errors.length) throw new Error('browser-runtime-errors:' + errors.join('|'));
  process.stdout.write(JSON.stringify({ status: 'passed', selected, executed: selected, skipped: 0 }) + '\n');
} finally {
  await browser.close();
}
