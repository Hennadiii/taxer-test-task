// utils/cert-parser.ts
//
// Парсить DER X.509 сертифікати через asn1js без pkijs.
// Дати читаються з valueBeforeDecode (raw bytes) → ASCII рядок,
// бо asn1js залишає valueBlock.value порожнім для UTCTime/GeneralizedTime.

import * as fs from 'fs';
import * as path from 'path';
import * as asn1js from 'asn1js';

export interface CertData {
  commonName: string;
  issuerName: string;
  validFrom: string;
  validTo: string;
  validFromShort: string;
  validToShort: string;
}

// ─── Дата ────────────────────────────────────────────────────────────────────

/**
 * Читає дату з ASN.1 UTCTime або GeneralizedTime вузла.
 *
 * asn1js зберігає сирі байти в valueBlock.valueBeforeDecode (Uint8Array).
 * UTCTime:         YYMMDDHHMMSSZ         (13 байт)
 * GeneralizedTime: YYYYMMDDHHMMSSZ       (15 байт)
 */
function parseDateNode(node: any): Date {
  const vb = node?.valueBlock;

  // Спочатку пробуємо valueBeforeDecode (Uint8Array з ASCII байтами дати)
  let raw: Uint8Array | null = null;
  if (vb?.valueBeforeDecode instanceof Uint8Array && vb.valueBeforeDecode.length > 0) {
    raw = vb.valueBeforeDecode;
  } else if (vb?.valueHex instanceof ArrayBuffer) {
    raw = new Uint8Array(vb.valueHex);
  }

  if (!raw || raw.length === 0) {
    throw new Error('Порожній valueBeforeDecode у вузлі дати');
  }

  // Декодуємо байти як ASCII рядок
  const str = String.fromCharCode(...Array.from(raw));

  return parseTimeString(str, node?.idBlock?.tagNumber);
}

/**
 * Парсить рядок дати:
 *   UTCTime (tag 23):         "YYMMDDHHMMSSZ"
 *   GeneralizedTime (tag 24): "YYYYMMDDHHMMSSZ"
 */
function parseTimeString(str: string, tagNumber: number): Date {
  // Прибираємо суфікс 'Z' або '+0000'
  const s = str.replace(/Z$/, '').replace(/[+\-]\d{4}$/, '');

  let year: number, month: number, day: number;
  let hour: number, min: number, sec: number;

  if (tagNumber === 24 || s.length === 14) {
    // GeneralizedTime: YYYYMMDDHHMMSS
    year  = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10);
    day   = parseInt(s.slice(6, 8), 10);
    hour  = parseInt(s.slice(8, 10), 10);
    min   = parseInt(s.slice(10, 12), 10);
    sec   = parseInt(s.slice(12, 14), 10);
  } else {
    // UTCTime: YYMMDDHHMMSS
    const yy = parseInt(s.slice(0, 2), 10);
    year  = yy >= 50 ? 1900 + yy : 2000 + yy; // RFC 5280: >= 50 → 19xx
    month = parseInt(s.slice(2, 4), 10);
    day   = parseInt(s.slice(4, 6), 10);
    hour  = parseInt(s.slice(6, 8), 10);
    min   = parseInt(s.slice(8, 10), 10);
    sec   = parseInt(s.slice(10, 12), 10);
  }

  return new Date(Date.UTC(year, month - 1, day, hour, min, sec));
}

function formatDate(date: Date): { full: string; short: string } {
  const pad = (n: number) => String(n).padStart(2, '0');
  const short = `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
  const full  = `${short} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`;
  return { full, short };
}

// ─── CN з RDN ────────────────────────────────────────────────────────────────

function ch(node: any): any[] {
  return node?.valueBlock?.value ?? [];
}

/**
 * Витягує CN (OID 2.5.4.3) з RDN SEQUENCE.
 * Значення дістається з valueBlock.value (рядок) або
 * через valueBeforeDecode (байти → UTF-8) для кириличних рядків.
 */
function extractCN(rdnNode: any): string {
  for (const set of ch(rdnNode)) {
    for (const attr of ch(set)) {
      const attrCh = ch(attr);
      if (attrCh.length < 2) continue;

      const oidNode = attrCh[0];
      const valNode = attrCh[1];

      // OID як рядок
      const oid: string =
        oidNode?.valueBlock?.toString?.()
        ?? String(oidNode?.valueBlock?.value ?? '');

      if (oid !== '2.5.4.3') continue;

      // Спочатку пробуємо звичайне .value
      const direct = valNode?.valueBlock?.value;
      if (typeof direct === 'string' && direct.length > 0) return direct;

      // Fallback: декодуємо з valueBeforeDecode як UTF-8
      const raw: Uint8Array | undefined = valNode?.valueBlock?.valueBeforeDecode;
      if (raw instanceof Uint8Array && raw.length > 0) {
        return Buffer.from(raw).toString('utf8');
      }

      return 'Unknown';
    }
  }
  return 'Unknown';
}

// ─── Головна функція ──────────────────────────────────────────────────────────

export function parseCertificate(filePath: string): CertData {
  let buf = fs.readFileSync(filePath);

  // PEM → DER
  const str = buf.toString('utf8');
  if (str.includes('-----BEGIN')) {
    const b64 = str.replace(/-----[^\n]+\n?/g, '').replace(/\s+/g, '');
    buf = Buffer.from(b64, 'base64');
  }

  const der: ArrayBuffer = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

  const asn1 = asn1js.fromBER(der);
  if (asn1.offset === -1) throw new Error(`ASN.1 decode error: ${path.basename(filePath)}`);

  const tbs    = ch(asn1.result)[0];
  const tbsCh  = ch(tbs);

  // version [0] має tagClass=3, tagNumber=0
  const offset = (tbsCh[0]?.idBlock?.tagClass === 3 && tbsCh[0]?.idBlock?.tagNumber === 0) ? 1 : 0;

  const issuerNode   = tbsCh[offset + 2]; // issuer
  const validityNode = tbsCh[offset + 3]; // validity
  const subjectNode  = tbsCh[offset + 4]; // subject

  const validityCh = ch(validityNode);
  const notBeforeDate = parseDateNode(validityCh[0]);
  const notAfterDate  = parseDateNode(validityCh[1]);

  const from = formatDate(notBeforeDate);
  const to   = formatDate(notAfterDate);

  return {
    commonName:     extractCN(subjectNode),
    issuerName:     extractCN(issuerNode),
    validFrom:      from.full,
    validTo:        to.full,
    validFromShort: from.short,
    validToShort:   to.short,
  };
}