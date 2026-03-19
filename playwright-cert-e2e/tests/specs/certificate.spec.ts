// tests/specs/certificate.spec.ts
import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { parseCertificate, CertData } from '../../utils/cert-parser';

const BASE_URL  = 'https://js-qvfsmdwp.stackblitz.io/';
const CERTS_DIR = path.join(__dirname, '../fixtures');

const certFiles = fs
  .readdirSync(CERTS_DIR)
  .filter(f => f.endsWith('.cer') || f.endsWith('.crt'));

function cellByHeader(page: import('@playwright/test').Page, thText: string) {
  return page.locator(`table tr:has(th:text-is("${thText}")) td`);
}

async function expectDate(
  page: import('@playwright/test').Page,
  thText: string,
  full: string,
  short: string
) {
  const cell = cellByHeader(page, thText);
  const text = await cell.innerText();
  expect(text).toContain(text.includes(':') ? full : short);
}

/**
 * Емулює drag & drop файлу у dropbox через DataTransfer API.
 * Це єдиний спосіб передати файл у dropzone без нативного filechooser.
 */
async function dropFile(
  page: import('@playwright/test').Page,
  selector: string,
  filePath: string
) {
  const fileName = path.basename(filePath);
  const fileContent = fs.readFileSync(filePath);
  const base64 = fileContent.toString('base64');
  const mimeType = 'application/x-x509-ca-cert';

  await page.evaluate(
    async ({ selector, base64, fileName, mimeType }) => {
      // Декодуємо base64 → Uint8Array → File
      const byteChars = atob(base64);
      const byteArr = new Uint8Array(byteChars.length);
      for (let i = 0; i < byteChars.length; i++) {
        byteArr[i] = byteChars.charCodeAt(i);
      }
      const file = new File([byteArr], fileName, { type: mimeType });

      // Будуємо DataTransfer з файлом
      const dt = new DataTransfer();
      dt.items.add(file);

      const el = document.querySelector(selector) as HTMLElement;
      if (!el) throw new Error(`Елемент не знайдено: ${selector}`);

      // Стріляємо події drag & drop
      el.dispatchEvent(new DragEvent('dragenter', { bubbles: true, dataTransfer: dt }));
      el.dispatchEvent(new DragEvent('dragover',  { bubbles: true, dataTransfer: dt }));
      el.dispatchEvent(new DragEvent('drop',      { bubbles: true, dataTransfer: dt }));
      el.dispatchEvent(new DragEvent('dragleave', { bubbles: true, dataTransfer: dt }));
    },
    { selector, base64, fileName, mimeType }
  );
}

test.describe('E2E: Завантаження та перевірка сертифікатів', () => {
  test.setTimeout(120_000);

  for (const fileName of certFiles) {
    test(`Файл: ${fileName}`, async ({ page }) => {
      const filePath = path.join(CERTS_DIR, fileName);

      // 1. Парсимо сертифікат
      let certInfo: CertData;
      try {
        certInfo = parseCertificate(filePath);
      } catch (err) {
        console.warn(`⚠️  Пропускаємо: ${fileName} — ${err}`);
        test.skip();
        return;
      }
      console.log(`📋 [${fileName}]`, certInfo);

      // 2. Відкриваємо сайт
      await page.goto(BASE_URL, { waitUntil: 'networkidle' });

      const runBtn = page.getByRole('button', { name: 'Run this project' });
      if (await runBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
        await runBtn.click();
        await page.waitForLoadState('networkidle');
      }

      // 3. Клікаємо кнопку відкриття dropbox
      const uploadBtn = page.locator('button.btn-primary').first();
      await uploadBtn.waitFor({ state: 'attached', timeout: 15_000 });
      await uploadBtn.dispatchEvent('click');

      // 4. Чекаємо поки dropbox стане видимим
      const dropbox = page.locator('.dropbox');
      await dropbox.waitFor({ state: 'visible', timeout: 10_000 });

      // 5. Передаємо файл через емуляцію drag & drop
      await dropFile(page, '.dropbox', filePath);

      // 6. Перевірка списку зліва
      const listItem = page.locator('.list-group-item', { hasText: certInfo.commonName });
      await expect(listItem).toBeVisible({ timeout: 15_000 });
      await listItem.click();

      // 7. Чекаємо таблицю деталей
      const table = page.locator('.card table');
      await table.waitFor({ state: 'visible', timeout: 10_000 });

      // 8. Перевіряємо поля таблиці
      await expect(cellByHeader(page, 'SubjectCN:')).toContainText(certInfo.commonName);
      await expect(cellByHeader(page, 'IssuerCN:')).toContainText(certInfo.issuerName);
      await expectDate(page, 'ValidFrom:', certInfo.validFrom, certInfo.validFromShort);
      await expectDate(page, 'ValidTill:', certInfo.validTo,   certInfo.validToShort);

      console.log(`✅ [${fileName}] ${certInfo.commonName}`);
    });
  }
});