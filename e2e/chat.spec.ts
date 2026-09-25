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
