// scripts/diagnose-certs.ts
// Запуск: npx ts-node scripts/diagnose-certs.ts
import * as fs from 'fs';
import * as path from 'path';
import * as asn1js from 'asn1js';

const CERTS_DIR = path.join(__dirname, '../tests/fixtures');

const files = fs.readdirSync(CERTS_DIR)
  .filter(f => f.endsWith('.cer') || f.endsWith('.crt'))
  .filter(f => !f.includes('Тестовий_платник')); // цей файл не є сертифікатом

/** Повертає дочірні вузли */
function ch(node: any): any[] {
  return node?.valueBlock?.value ?? [];
}

/** Серіалізує вузол для виводу */
function describeNode(node: any, label: string) {
  if (!node) { console.log(`   ${label}: undefined`); return; }
  const tagClass  = node?.idBlock?.tagClass;
  const tagNumber = node?.idBlock?.tagNumber;
  const vb        = node?.valueBlock;
  const vbType    = vb?.constructor?.name ?? typeof vb;
  const vbValue   = vb?.value;
  const vbValueType = typeof vbValue;
  const isDate    = vbValue instanceof Date;

  console.log(`   ${label}:`);
  console.log(`     tagClass=${tagClass} tagNumber=${tagNumber} (23=UTCTime 24=GeneralizedTime)`);
  console.log(`     valueBlock type: ${vbType}`);
  console.log(`     valueBlock.value type: ${vbValueType}, isDate: ${isDate}`);
  if (!isDate) {
    console.log(`     valueBlock.value raw: ${JSON.stringify(vbValue)?.slice(0, 80)}`);
  } else {
    console.log(`     Date: ${vbValue}`);
  }
  // Додаткові поля які може мати valueBlock
  const keys = Object.keys(vb ?? {}).filter(k => k !== 'value');
  if (keys.length) console.log(`     valueBlock extra keys: ${keys.join(', ')}`);
}

for (const fileName of files) {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`📄 ${fileName}`);

  const filePath = path.join(CERTS_DIR, fileName);
  const buf = fs.readFileSync(filePath);
  const der: ArrayBuffer = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

  try {
    const asn1 = asn1js.fromBER(der);
    if (asn1.offset === -1) { console.log('   ❌ ASN.1 decode failed'); continue; }

    const root = asn1.result;
    const tbs  = ch(root)[0];
    const tbsCh = ch(tbs);

    // Визначаємо offset (чи є version [0])
    const maybeVersion = tbsCh[0];
    const hasVersion = maybeVersion?.idBlock?.tagClass === 3 && maybeVersion?.idBlock?.tagNumber === 0;
    const offset = hasVersion ? 1 : 0;
    console.log(`   hasVersion: ${hasVersion}, offset: ${offset}`);
    console.log(`   TBS children count: ${tbsCh.length}`);

    // Виводимо типи всіх дітей TBS
    tbsCh.forEach((c: any, i: number) => {
      const tc = c?.idBlock?.tagClass;
      const tn = c?.idBlock?.tagNumber;
      const nc = ch(c).length;
      console.log(`   tbs[${i}]: tagClass=${tc} tagNumber=${tn} children=${nc}`);
    });

    // Дивимося validity вузол
    const validityNode = tbsCh[offset + 3];
    console.log(`\n   → validity = tbs[${offset + 3}]:`);
    const validityCh = ch(validityNode);
    console.log(`     children count: ${validityCh.length}`);
    describeNode(validityCh[0], 'notBefore');
    describeNode(validityCh[1], 'notAfter');

  } catch (e) {
    console.log(`   ❌ Error: ${e}`);
  }
}