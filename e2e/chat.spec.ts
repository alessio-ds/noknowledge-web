import { readFileSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';

const PASSWORD = 'correct-horse-battery';

async function createAccount(page: Page, name: string): Promise<string> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create a new identity' }).click();
  await page.getByPlaceholder('Alice').fill(name);
  const passwords = page.locator('input[type="password"]');
  await passwords.nth(0).fill(PASSWORD);
  await passwords.nth(1).fill(PASSWORD);
  await page.getByRole('button', { name: 'Continue' }).click();

  await expect(page.getByRole('heading', { name: 'Save your seed phrase' })).toBeVisible();
  const mnemonic = await page.locator('.mnemonic span').allInnerTexts();
  await page.getByRole('button', { name: /I saved it/ }).click();
  await expect(page.getByTestId('my-card')).toBeVisible({ timeout: 90_000 });
  return mnemonic.join(' ').replace(/\d+/g, '').replace(/\s+/g, ' ').trim();
}

async function readCard(page: Page): Promise<string> {
  await page.getByTestId('my-card').click();
  const textarea = page.getByTestId('card-string');
  await expect(textarea).toBeVisible();
  const card = await textarea.inputValue();
  expect(card.startsWith('nk://1/')).toBe(true);
  await page.getByLabel('Close dialog').click();
  await expect(textarea).toBeHidden();
  return card;
}

test('two users exchange a message and an encrypted file', async ({ browser }) => {
  const aliceContext = await browser.newContext();
  const bobContext = await browser.newContext();
  const alice = await aliceContext.newPage();
  const bob = await bobContext.newPage();

  await createAccount(alice, 'Alice');
  await createAccount(bob, 'Bob');

  const aliceCard = await readCard(alice);

  // Bob adds Alice and opens the conversation.
  await bob.getByTestId('open-add').click();
  await bob.getByTestId('add-card').fill(aliceCard);
  await bob.getByTestId('submit-add').click();
  await expect(bob.getByTestId('composer')).toBeVisible();

  await bob.getByTestId('composer').fill('hello from bob');
  await bob.getByTestId('send').click();
  await expect(bob.getByTestId('bubble').filter({ hasText: 'hello from bob' })).toBeVisible();

  // Alice learns the contact from the first message's sealed card.
  await expect(alice.getByTestId('contact')).toHaveCount(1, { timeout: 90_000 });
  await alice.getByTestId('contact').first().click();
  await expect(
    alice.getByTestId('bubble').filter({ hasText: 'hello from bob' }),
  ).toBeVisible({ timeout: 90_000 });

  // Alice replies; Bob receives it.
  await alice.getByTestId('composer').fill('hi bob');
  await alice.getByTestId('send').click();
  await expect(bob.getByTestId('messages')).toContainText('hi bob', { timeout: 90_000 });

  // Bob sends a file; Alice decrypts and downloads the exact bytes.
  await bob
    .getByTestId('attach-input')
    .setInputFiles({ name: 'note.txt', mimeType: 'text/plain', buffer: Buffer.from('secret file contents') });

  await expect(alice.getByTestId('download')).toBeVisible({ timeout: 90_000 });
  const downloadPromise = alice.waitForEvent('download');
  await alice.getByTestId('download').last().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('note.txt');
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  expect(Buffer.concat(chunks).toString('utf8')).toBe('secret file contents');

  await aliceContext.close();
  await bobContext.close();
});

test('an account survives sign-out and unlocks from the passphrase', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await createAccount(page, 'Carol');

  const card = await readCard(page);
  await page.getByTestId('open-settings').click();
  await page.getByRole('button', { name: 'Sign out' }).click();

  // Back at the landing screen: the account is listed, and unlocks with the password.
  await page.getByRole('button', { name: 'Unlock' }).first().click();
  await page.locator('input[type="password"]').first().fill(PASSWORD);
  await page.getByRole('button', { name: 'Unlock' }).last().click();
  await expect(page.getByTestId('my-card')).toBeVisible({ timeout: 90_000 });
  const cardAgain = await readCard(page);
  expect(cardAgain).toBe(card);

  await context.close();
});

test('recovers an account from its seed phrase', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const mnemonic = await createAccount(page, 'Dave');
  const card = await readCard(page);

  await page.getByTestId('open-settings').click();
  await page.getByRole('button', { name: 'Sign out' }).click();

  await page.getByRole('button', { name: 'Import from a seed phrase' }).click();
  await page.getByPlaceholder('Alice').fill('Dave');
  await page.locator('textarea').first().fill(mnemonic);
  await page.locator('input[type="password"]').first().fill(PASSWORD);
  await page.getByRole('button', { name: 'Import' }).click();
  await expect(page.getByTestId('my-card')).toBeVisible({ timeout: 90_000 });

  const recoveredCard = await readCard(page);
  expect(recoveredCard).toBe(card);
  await context.close();
});

test('lists the account devices, and a recovered device joins them', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const mnemonic = await createAccount(page, 'Erin');

  // A fresh account has exactly one device: this browser.
  await page.getByTestId('my-devices').click();
  await expect(page.getByTestId('device-list')).toBeVisible({ timeout: 45_000 });
  await expect(page.getByTestId('device-list').locator('li')).toHaveCount(1);
  // Both devices carry the account name, so the marker is what tells them apart.
  await expect(page.getByTestId('device-list').locator('li').first()).toContainText('this device');
  await page.getByLabel('Close dialog').click();

  // Restoring the seed phrase in a second browser profile adds a device, and the
  // account's list grows to two without either side doing anything else.
  const second = await browser.newContext();
  const other = await second.newPage();
  await other.goto('/');
  await other.getByRole('button', { name: 'Import from a seed phrase' }).click();
  await other.getByPlaceholder('Alice').fill('Erin');
  await other.locator('textarea').first().fill(mnemonic);
  await other.locator('input[type="password"]').first().fill(PASSWORD);
  await other.getByRole('button', { name: 'Import' }).click();
  await expect(other.getByTestId('my-card')).toBeVisible({ timeout: 90_000 });

  await other.getByTestId('my-devices').click();
  await expect(other.getByTestId('device-list').locator('li')).toHaveCount(2, { timeout: 45_000 });
  await expect(other.getByTestId('device-list').locator('li').last()).toContainText('this device');

  await second.close();
  await context.close();
});

test('the sidebar actions stay on one line and inside the sidebar', async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await createAccount(page, 'Frank');

  const layout = await page.evaluate(() => {
    const row = document.querySelector('[data-testid="sidebar-actions"]') as HTMLElement;
    const sidebar = document.querySelector('.sidebar') as HTMLElement;
    const gear = document.querySelector('[data-testid="open-settings"]') as HTMLElement;
    const idLabel = sidebar.querySelector('.id') as HTMLElement;
    const buttons = Array.from(row.querySelectorAll('button')) as HTMLElement[];
    return {
      sidebarWidth: Math.round(sidebar.getBoundingClientRect().width),
      sidebarRight: sidebar.getBoundingClientRect().right,
      gearRight: Math.round(gear.getBoundingClientRect().right),
      // A clipped identity id would mean the header no longer fits.
      idOverflow: idLabel.scrollWidth - idLabel.clientWidth,
      buttons: buttons.map((button) => {
        const box = button.getBoundingClientRect();
        // Height of the label itself, so padding cannot fake a single line.
        const range = document.createRange();
        range.selectNodeContents(button);
        const textHeight = range.getBoundingClientRect().height;
        return {
          label: (button.textContent ?? '').trim(),
          top: Math.round(box.top),
          right: Math.round(box.right),
          // scrollWidth > clientWidth means the label wrapped or clipped.
          overflow: button.scrollWidth - button.clientWidth,
          lines: Math.round(textHeight / parseFloat(getComputedStyle(button).lineHeight)),
        };
      }),
    };
  });

  expect(layout.buttons.map((button) => button.label)).toEqual(['My card', 'Devices', 'Add contact']);
  // Same line: every button shares one top edge.
  expect(new Set(layout.buttons.map((button) => button.top)).size).toBe(1);
  for (const button of layout.buttons) {
    expect(button.overflow, `${button.label} wrapped or clipped`).toBeLessThanOrEqual(0);
    expect(button.lines, `${button.label} is not on a single line`).toBe(1);
    expect(button.right, `${button.label} runs past the sidebar`).toBeLessThanOrEqual(
      layout.sidebarRight,
    );
  }

  // The gear lives in the header and stays inside the sidebar.
  expect(layout.sidebarWidth).toBeGreaterThanOrEqual(320);
  expect(layout.gearRight).toBeLessThanOrEqual(layout.sidebarRight);
  expect(layout.idOverflow).toBeLessThanOrEqual(0);

  // Settings moved out of that row, and still opens the modal.
  await page.getByTestId('open-settings').click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();

  await context.close();
});

test('exports history to a file and imports it back', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await createAccount(page, 'Grace');

  // A conversation to export: write to ourselves is not possible, so just make
  // sure the export path produces a file and reports it.
  await page.getByTestId('my-devices').click();
  await expect(page.getByTestId('device-list')).toBeVisible({ timeout: 45_000 });
  await page.getByTestId('history-passphrase').fill('export-passphrase');
  await page.getByTestId('history-range').selectOption('all');

  const download = page.waitForEvent('download');
  await page.getByTestId('export-history').click();
  const saved = await download;
  const path = await saved.path();
  expect(path).toBeTruthy();
  const bytes = readFileSync(path!);
  expect(bytes.subarray(0, 4).toString('utf8')).toBe('NKX1');

  // The same file imports cleanly (nothing new, but no error either).
  await page.getByTestId('history-passphrase').fill('export-passphrase');
  await page.getByTestId('import-history').setInputFiles(path!);
  await expect(page.getByTestId('history-status')).toContainText('Merged 0 new message(s)', {
    timeout: 45_000,
  });

  await context.close();
});

test('a restored device asks for history and the other device approves it', async ({ browser }) => {
  const first = await browser.newContext();
  const laptop = await first.newPage();
  const mnemonic = await createAccount(laptop, 'Heidi');

  // A second device for the same account.
  const second = await browser.newContext();
  const phone = await second.newPage();
  await phone.goto('/');
  await phone.getByRole('button', { name: 'Import from a seed phrase' }).click();
  await phone.getByPlaceholder('Alice').fill('Heidi');
  await phone.locator('textarea').first().fill(mnemonic);
  await phone.locator('input[type="password"]').first().fill(PASSWORD);
  await phone.getByRole('button', { name: 'Import' }).click();
  await expect(phone.getByTestId('my-card')).toBeVisible({ timeout: 90_000 });

  // The new device asks for the past. Nobody has approved it yet.
  await phone.getByTestId('my-devices').click();
  await expect(phone.getByTestId('device-list').locator('li')).toHaveCount(2, { timeout: 45_000 });
  await phone.getByTestId('request-history').click();
  await expect(phone.getByTestId('sync-note')).toContainText('Approve the request there', {
    timeout: 45_000,
  });
  await phone.getByLabel('Close dialog').click();

  // The laptop sees the request and approves it — the click a stolen seed
  // cannot make on its own.
  await expect(async () => {
    // Close the modal if a previous attempt left it open, then reopen it so the
    // dialog re-reads the requests from the client.
    const close = laptop.getByLabel('Close dialog');
    if ((await close.count()) > 0) await close.first().click();
    await laptop.getByTestId('my-devices').click();
    await expect(laptop.getByTestId('sync-requests')).toBeVisible({ timeout: 8_000 });
  }).toPass({ timeout: 120_000 });
  await laptop.getByRole('button', { name: 'Approve' }).click();
  await expect(laptop.getByTestId('sync-note')).toContainText('mirror to it too', {
    timeout: 45_000,
  });
  await laptop.getByLabel('Close dialog').click();

  // The phone now knows it was approved.
  await expect(async () => {
    const close = phone.getByLabel('Close dialog');
    if ((await close.count()) > 0) await close.first().click();
    await phone.getByTestId('my-devices').click();
    await expect(phone.getByTestId('device-list')).toContainText('history approved', {
      timeout: 8_000,
    });
    await close.first().click();
  }).toPass({ timeout: 120_000 });

  await second.close();
  await first.close();
});
