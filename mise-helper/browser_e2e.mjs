import { chromium } from 'playwright';

const reasons = new Set([
  'e2e-request-invalid', 'e2e-browser-missing', 'e2e-browser-failed',
  'e2e-page-failed', 'e2e-render-failed', 'e2e-resize-failed', 'e2e-timeout',
]);
let browser;
let timer;
let reason = 'e2e-browser-failed';

try {
  const [origin, mode, ...extra] = process.argv.slice(2);
  const url = new URL(origin);
  if (extra.length || !['fast', 'full'].includes(mode)
      || !['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.search || url.hash || url.pathname !== '/') {
    throw new Error('e2e-request-invalid');
  }
  const run = async () => {
    try {
      browser = await chromium.launch({
        headless: true,
        args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader'],
      });
    } catch {
      throw new Error('e2e-browser-missing');
    }
    const context = await browser.newContext({
      viewport: { width: 1280, height: 720 }, deviceScaleFactor: 1,
      serviceWorkers: 'block',
    });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    let pageFailed = false;
    page.on('pageerror', () => { pageFailed = true; });
    page.on('requestfailed', () => { pageFailed = true; });
    page.on('response', (response) => {
      if (response.status() >= 400
          && ['document', 'script', 'stylesheet'].includes(response.request().resourceType())) {
        pageFailed = true;
      }
    });
    await context.route('**/*', async (route) => {
      if (new URL(route.request().url()).origin !== url.origin) {
        pageFailed = true;
        await route.abort();
      } else {
        await route.continue();
      }
    });
    const response = await page.goto(url.href, { waitUntil: 'networkidle', timeout: 30000 });
    if (!response || response.status() !== 200 || new URL(page.url()).origin !== url.origin
        || await page.title() !== 'Apple Tree') {
      throw new Error('e2e-page-failed');
    }
    const checkFrame = async (width, height, failure) => {
      await page.waitForFunction(({ width, height }) => {
        const canvas = document.querySelector('#scene');
        if (!canvas || canvas.dataset.skyFeature !== 'sun-disc') return false;
        const gl = canvas.getContext('webgl2');
        return gl && !gl.isContextLost() && canvas.clientWidth === width
          && canvas.clientHeight === height && gl.drawingBufferWidth === width
          && gl.drawingBufferHeight === height;
      }, { width, height });
      const picture = await page.locator('#scene').screenshot({ timeout: 15000 });
      if (pageFailed || picture.length < 1000) throw new Error(failure);
    };
    reason = 'e2e-render-failed';
    await checkFrame(1280, 720, reason);
    if (mode === 'full') {
      reason = 'e2e-resize-failed';
      await page.setViewportSize({ width: 800, height: 600 });
      await checkFrame(800, 600, reason);
    }
    const count = mode === 'full' ? 2 : 1;
    return { status: 'passed', selected: count, executed: count, skipped: 0 };
  };
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('e2e-timeout')), 100000);
  });
  const result = await Promise.race([run(), timeout]);
  process.stdout.write(JSON.stringify(result) + '\n');
} catch (error) {
  const safeReason = reasons.has(error.message) ? error.message : reason;
  process.stdout.write(JSON.stringify({ status: 'blocked', reason_code: safeReason }) + '\n');
  process.exitCode = 1;
} finally {
  clearTimeout(timer);
  if (browser) await browser.close();
}
