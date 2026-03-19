// scripts/debug-iframe.ts
// Запуск: npx ts-node scripts/debug-iframe.ts
// Відкриває сайт, чекає 20 секунд і виводить ВСІ iframe на сторінці

import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({ headless: false }); // відкрити браузер візуально
  const page = await browser.newPage();

  console.log('Відкриваємо сайт...');
  await page.goto('https://js-qvfsmdwp.stackblitz.io/', { waitUntil: 'domcontentloaded' });

  // Клікаємо Run якщо є
  try {
    const runBtn = page.getByRole('button', { name: 'Run this project' });
    await runBtn.waitFor({ timeout: 5000 });
    await runBtn.click();
    console.log('Клікнули Run this project');
  } catch {
    console.log('Кнопки Run this project немає');
  }

  // Чекаємо поки щось завантажиться
  await page.waitForTimeout(8000);

  // Виводимо всі iframe
  const frames = page.frames();
  console.log(`\nВсього frames: ${frames.length}`);
  for (const frame of frames) {
    console.log(`  url: ${frame.url()}`);
    console.log(`  name: ${frame.name()}`);
  }

  // Виводимо всі <iframe> елементи через DOM
  const iframes = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('iframe')).map(el => ({
      src: el.src,
      id: el.id,
      className: el.className,
      title: el.title,
      name: el.name,
    }));
  });
  console.log(`\n<iframe> елементів у DOM: ${iframes.length}`);
  iframes.forEach((f, i) => console.log(`  [${i}]`, JSON.stringify(f)));

  // Перевіряємо чи є кнопка на головній сторінці
  const btnOnPage = await page.locator('button:has-text("Завантажити")').count();
  console.log(`\nКнопка "Завантажити" на головній сторінці: ${btnOnPage}`);

  await page.waitForTimeout(3000);
  await browser.close();
})();