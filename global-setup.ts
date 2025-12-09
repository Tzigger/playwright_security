import { chromium, FullConfig } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';

const DEFAULT_BWAPP_URL = 'http://localhost:8080';
const STORAGE_STATE_PATH = path.join(__dirname, 'storage-states', 'bwapp-auth.json');

async function ensureDirExists(filePath: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
}

async function loginToBwapp(baseUrl: string): Promise<void> {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ baseURL: baseUrl });
  const page = await context.newPage();

  await page.goto('/login.php');
  await page.waitForSelector('input[name="login"]');
  await page.getByRole('textbox', { name: 'Login:' }).fill(process.env.BWAPP_USER ?? 'bee');
  await page.getByRole('textbox', { name: 'Password:' }).fill(process.env.BWAPP_PASSWORD ?? 'bug');
  await page.locator('select[name="security_level"]').selectOption(process.env.BWAPP_SECURITY_LEVEL ?? '0');
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForURL('**/portal.php');

  await ensureDirExists(STORAGE_STATE_PATH);
  await context.storageState({ path: STORAGE_STATE_PATH });

  await browser.close();
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  const bwappUrl = process.env.BWAPP_URL ?? DEFAULT_BWAPP_URL;
  await loginToBwapp(bwappUrl);
}
