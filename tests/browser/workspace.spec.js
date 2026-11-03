import { expect, test } from '@playwright/test';

// Runs against the temporary database and allowlist in scripts/qa_server.py.
test('team workflow, pasted images, and half-screen layouts', async ({ page, browser }, testInfo) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill('sohee');
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Home', exact: true })).toBeVisible();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Scope', exact: true }).click();
  await expect(page).toHaveURL(/\/scope$/);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Scope', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Add scope', exact: true }).click();
  await page.getByLabel('Subnets, one per line').fill('10.20.0.0/24 Corporate');
  await page.getByLabel('Discover hosts after adding networks').uncheck();
  await page.getByRole('button', { name: 'Add to scope' }).click();
  await page.getByLabel('Nmap XML files').setInputFiles('tests/fixtures/scan.xml');
  await page.getByRole('button', { name: 'dc01.corp.local', exact: true }).click();
  await expect(page).toHaveURL(/\/scope\?host=/);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'dc01.corp.local', exact: true })).toBeVisible();
  await page.getByLabel('Status', { exact: true }).selectOption('Investigating');
  await page.getByLabel('Owner', { exact: true }).selectOption('alex');
  await page.getByLabel('Notes', { exact: true }).fill('**Reviewing SMB signing.**\n');
  await page.getByRole('button', { name: 'Save host' }).click();
  await expect(page.getByText('Saved to team workspace.')).toBeVisible();
  await expect(page.locator('.host-table tr').filter({ hasText: 'dc01.corp.local' }).getByText('alex', { exact: true })).toBeVisible();
  await page.locator('.service-group summary').filter({ hasText: 'Microsoft RPC' }).click();
  await expect(page.locator('.host-detail').getByText('135/tcp', { exact: true })).toBeVisible();
  const divider = page.getByRole('separator', { name: 'Resize host details' });
  const beforeWidth = Number(await divider.getAttribute('aria-valuenow'));
  await divider.focus();
  await page.keyboard.press('ArrowLeft');
  await expect(divider).toHaveAttribute('aria-valuenow', String(beforeWidth + 16));
  const handle = await divider.boundingBox();
  await page.mouse.move(handle.x + handle.width / 2, handle.y + 100);
  await page.mouse.down();
  await page.mouse.move(handle.x - 40, handle.y + 100);
  await page.mouse.up();
  expect(Number(await divider.getAttribute('aria-valuenow'))).toBeGreaterThan(beforeWidth + 16);
  await page.screenshot({ path: testInfo.outputPath('scope-desktop.png'), fullPage: true });

  // A half-width desktop should focus the selected host, with no below-the-table hunting.
  await page.setViewportSize({ width: 800, height: 900 });
  await expect(page.getByRole('button', { name: 'Back to hosts' })).toBeVisible();
  await expect(page.locator('.scope-main')).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('scope-half-screen.png'), fullPage: true });
  await page.getByRole('button', { name: 'Back to hosts' }).click();
  await page.getByRole('button', { name: 'dc01.corp.local', exact: true }).click();
  await page.getByRole('button', { name: 'New finding', exact: true }).click();
  await page.getByLabel('Vulnerability title').fill('SMB signing is not required');
  await expect(page.locator('.scope-option').getByRole('checkbox').first()).toBeChecked();
  await page.locator('.port-option').filter({ hasText: '445/tcp' }).getByRole('checkbox').check();
  await page.getByLabel('Vulnerability description', { exact: true }).fill('Evidence: ');
  await page.getByLabel('Vulnerability description', { exact: true }).evaluate(element => {
    element.focus();
    element.setSelectionRange(element.value.length, element.value.length);
    const canvas = document.createElement('canvas');
    canvas.width = 32; canvas.height = 16;
    const context = canvas.getContext('2d');
    context.fillStyle = '#4160c8'; context.fillRect(0, 0, 32, 16);
    return new Promise(resolve => canvas.toBlob(blob => {
      const transfer = new DataTransfer();
      transfer.items.add(new File([blob], 'evidence.png', { type: 'image/png' }));
      element.dispatchEvent(new ClipboardEvent('paste', { clipboardData: transfer, bubbles: true, cancelable: true }));
      resolve();
    }, 'image/png'));
  });
  await expect(page.getByLabel('Vulnerability description', { exact: true })).toHaveValue(/Evidence: !\[image\]\(http:\/\/127\.0\.0\.1:8765\/api\/attachments\/[a-f0-9]+\)/);
  await page.getByLabel('Steps to reproduce', { exact: true }).fill('1. Inspect the imported SMB security-mode output.');
  await page.getByLabel('Remediation steps', { exact: true }).fill('Require SMB signing.');
  await page.getByRole('button', { name: 'Save finding' }).click();
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible();
  await expect(page.getByText('Finding saved.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'SMB signing is not required', exact: true }).click();
  await page.getByRole('button', { name: 'Preview report' }).click();
  await expect(page.locator('.report-preview img')).toBeVisible();
  expect(await page.locator('.report-preview img').evaluate(img => img.complete && img.naturalWidth > 0)).toBe(true);

  // A separate logged-in teammate can read the same finding and image.
  const teammate = await browser.newContext({ baseURL: 'http://127.0.0.1:8765' });
  const login = await teammate.request.post('/api/login', { data: { username: 'alex' }, headers: { 'X-Kiss-Request': '1' } });
  expect(login.ok()).toBe(true);
  const state = await (await teammate.request.get('/api/state')).json();
  expect(state.findings[0].scope[0].ports).toEqual(['445/tcp']);
  const url = state.findings[0].description.match(/!\[image\]\(([^)]+)\)/)[1];
  expect((await teammate.request.get(url)).ok()).toBe(true);
  const home = await teammate.newPage();
  await home.goto('/');
  await expect(home.getByRole('heading', { name: 'Home', exact: true })).toBeVisible();
  await expect(home.locator('.assigned-hosts')).toContainText('dc01.corp.local');
  await expect(home.locator('.activity-list')).toContainText('added a finding');
  await home.setViewportSize({ width: 800, height: 900 });
  expect(await home.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await home.locator('.assigned-hosts').getByRole('button').first().click();
  await expect(home.getByRole('heading', { name: 'dc01.corp.local', exact: true })).toBeVisible();
  const anonymous = await browser.newContext();
  expect((await anonymous.request.get(url)).status()).toBe(401);
  await anonymous.close(); await teammate.close();

  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Dark theme', exact: true }).click();
  await page.screenshot({ path: testInfo.outputPath('finding-mobile-dark.png'), fullPage: true });
  expect(errors).toEqual([]);
});


test('credentials require scope and remain readable at half width', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill('sohee');
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Credentials', exact: true }).click();
  await page.getByRole('button', { name: 'Add credential', exact: true }).first().click();
  await page.getByLabel('Credential type', { exact: true }).selectOption('service');
  await expect(page.getByLabel('Service / application', { exact: true })).toHaveAttribute('required', '');
  await page.getByLabel('Service / application', { exact: true }).fill('PostgreSQL');
  await page.getByLabel('Hostname, IP, or endpoint', { exact: true }).fill('db01:5432');
  await page.getByLabel('Username', { exact: true }).fill('app_reader');
  await page.getByLabel('Password', { exact: true }).fill(' example-secret ');
  await page.getByRole('button', { name: 'Save credential', exact: true }).click();
  await expect(page.getByText('Credential saved to the team workspace.')).toBeVisible();
  await expect(page.locator('.credential-secret pre').filter({ hasText: 'example-secret' })).toBeVisible();
  await page.setViewportSize({ width: 640, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const row = page.locator('.credentials-table tr').filter({ hasText: 'app_reader' });
  await row.getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue(' example-secret ');
  await page.getByLabel('Status', { exact: true }).selectOption('Invalid');
  await page.getByRole('button', { name: 'Save credential', exact: true }).click();
  await expect(row.getByText('Invalid', { exact: true })).toBeVisible();
  await row.getByRole('button', { name: 'View credential for app_reader' }).click();
  await expect(page.getByRole('dialog', { name: 'Credential details' })).toBeVisible();
  await expect(page).toHaveURL(/\/credentials\?credential=/);
  await page.reload();
  await expect(page.getByRole('dialog', { name: 'Credential details' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await row.getByRole('button', { name: 'Edit', exact: true }).click();
  await page.getByLabel('Password', { exact: true }).fill('unsaved draft');
  await page.keyboard.press('Escape');
  await expect(page.locator('.credential-form')).toHaveCount(0);
  await row.getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('unsaved draft');
});


test('tab routes support reload and browser history', async ({ page }) => {
  await page.goto('/findings');
  await page.getByLabel('Username', { exact: true }).fill('sohee');
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible();
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await nav.getByRole('link', { name: 'Credentials', exact: true }).click();
  await expect(page).toHaveURL(/\/credentials$/);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible();
  await page.goForward();
  await expect(page.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible();
});


test('Escape warns before leaving an unsaved finding and preserves the draft', async ({ page }) => {
  await page.goto('/findings');
  await page.getByLabel('Username', { exact: true }).fill('sohee');
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await page.getByRole('button', { name: 'New finding', exact: true }).first().click();
  await page.getByLabel('Vulnerability title').fill('Unsaved team finding');
  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('Teammates will not see');
    await dialog.dismiss();
  });
  await page.keyboard.press('Escape');
  await expect(page.getByLabel('Vulnerability title')).toHaveValue('Unsaved team finding');
  page.once('dialog', dialog => dialog.accept());
  await page.keyboard.press('Escape');
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'New finding', exact: true }).first().click();
  await expect(page.getByLabel('Vulnerability title')).toHaveValue('Unsaved team finding');
});


test('admin opens user management from their name', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill('sohee');
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await page.getByRole('link', { name: 'Manage users (sohee)' }).click();
  await expect(page).toHaveURL(/\/users$/);
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download backup ZIP' }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toMatch(/^kiss-backup-.*\.zip$/);
  expect(await download.failure()).toBeNull();
  await page.locator('input[type="file"]').setInputFiles(await download.path());
  await expect(page.getByRole('heading', { name: 'Replace this workspace?' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Replace workspace', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Replace this workspace?' })).toHaveCount(0);
  const name = `teammate-${Date.now()}`;
  await page.getByLabel('Username', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'Add user', exact: true }).click();
  const row = page.locator('.user-list li').filter({ hasText: name });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Remove', exact: true }).click();
  await row.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(row).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/\/home$/);
});


test('host context menu replaces previous menus and dismisses cleanly', async ({ page }) => {
  await page.goto('/scope');
  await page.getByLabel('Username', { exact: true }).fill('sohee');
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await page.request.post('/api/scope', { headers: { 'X-Kiss-Request': '1' }, data: { kind: 'host', text: '10.99.0.1 menu-one\n10.99.0.2 menu-two', discover: false } });
  await page.reload();
  for (const name of ['menu-one', 'menu-two', 'menu-one', 'menu-one']) {
    await page.locator('.host-table tbody tr').filter({ hasText: name }).click({ button: 'right' });
    await expect(page.getByRole('menu')).toHaveCount(1);
    await expect(page.getByRole('menu')).toHaveAttribute('aria-label', `Actions for ${name}`);
  }
  await page.keyboard.press('Escape');
  await expect(page.getByRole('menu')).toHaveCount(0);
  await page.getByRole('button', { name: 'Actions for menu-two', exact: true }).click();
  await expect(page.getByRole('menu')).toHaveCount(1);
  await page.getByRole('menuitem', { name: 'Edit hostname' }).click();
  await expect(page.getByRole('menu')).toHaveCount(0);
  await expect(page.getByRole('dialog', { name: 'Edit hostname' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});
