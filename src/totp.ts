import { createHmac } from 'node:crypto';

export type TotpOptions = {
  digits: 6 | 8;
  period: 30 | 60;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
};

export type ParsedSeed = TotpOptions & {
  ok: true;
  seed: Buffer;
};

export type ParseSeedResult = ParsedSeed | {
  ok: false;
  reason: string;
};

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(input: string): Buffer | undefined {
  const normalized = input.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(normalized)) {
    return undefined;
  }

  const unpadded = normalized.replace(/=+$/, '');
  const remainder = unpadded.length % 8;
  if (![0, 2, 4, 5, 7].includes(remainder)) {
    return undefined;
  }

  const padding = normalized.length - unpadded.length;
  if (padding !== 0 && padding !== (8 - remainder) % 8) {
    return undefined;
  }

  const length = Math.floor(unpadded.length * 5 / 8);
  if (length < 10) {
    return undefined;
  }

  const seed = Buffer.alloc(length);
  let accumulator = 0;
  let bits = 0;
  let index = 0;

  for (const character of unpadded) {
    accumulator = (accumulator << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      seed[index++] = (accumulator >>> bits) & 0xff;
      accumulator &= (1 << bits) - 1;
    }
  }

  // Leftover low bits are ignored, as authenticator apps do: a hand-copied seed whose
  // encoder left them non-zero still makes the same codes.
  return seed;
}

export function parseSeed(input: string): ParseSeedResult {
  let secret = input;
  let digits: TotpOptions['digits'] = 6;
  let period: TotpOptions['period'] = 30;
  let algorithm: TotpOptions['algorithm'] = 'SHA1';

  if (/^otpauth:/i.test(input.trim())) {
    let uri: URL;
    try {
      uri = new URL(input.trim());
    } catch {
      return { ok: false, reason: 'Invalid authenticator URI.' };
    }

    if (
      uri.protocol !== 'otpauth:' ||
      uri.hostname !== 'totp' ||
      uri.username !== '' ||
      uri.password !== '' ||
      uri.port !== '' ||
      uri.hash !== ''
    ) {
      return { ok: false, reason: 'Unsupported authenticator URI.' };
    }

    for (const name of ['secret', 'digits', 'period', 'algorithm']) {
      if (uri.searchParams.getAll(name).length > 1) {
        return { ok: false, reason: 'Duplicate authenticator parameter.' };
      }
    }

    const uriSecret = uri.searchParams.get('secret');
    if (uriSecret === null) {
      return { ok: false, reason: 'Missing authenticator seed.' };
    }
    secret = uriSecret;

    const uriDigits = uri.searchParams.get('digits');
    if (uriDigits !== null) {
      if (uriDigits !== '6' && uriDigits !== '8') {
        return { ok: false, reason: 'Unsupported authenticator code length.' };
      }
      digits = uriDigits === '6' ? 6 : 8;
    }

    const uriPeriod = uri.searchParams.get('period');
    if (uriPeriod !== null) {
      if (uriPeriod !== '30' && uriPeriod !== '60') {
        return { ok: false, reason: 'Unsupported authenticator period.' };
      }
      period = uriPeriod === '30' ? 30 : 60;
    }

    const uriAlgorithm = uri.searchParams.get('algorithm');
    if (uriAlgorithm !== null) {
      const normalized = uriAlgorithm.toUpperCase();
      if (normalized !== 'SHA1' && normalized !== 'SHA256' && normalized !== 'SHA512') {
        return { ok: false, reason: 'Unsupported authenticator algorithm.' };
      }
      algorithm = normalized;
    }
  }

  const seed = decodeBase32(secret);
  if (seed === undefined) {
    return { ok: false, reason: 'Invalid authenticator seed.' };
  }

  return { ok: true, seed, digits, period, algorithm };
}

export function totpAt(seed: Buffer, unixSeconds: number, opts: TotpOptions): string {
  if (
    !Number.isFinite(unixSeconds) ||
    unixSeconds < 0 ||
    unixSeconds > Number.MAX_SAFE_INTEGER
  ) {
    throw new RangeError('Invalid authenticator time.');
  }
  if (
    (opts.digits !== 6 && opts.digits !== 8) ||
    (opts.period !== 30 && opts.period !== 60) ||
    !['SHA1', 'SHA256', 'SHA512'].includes(opts.algorithm)
  ) {
    throw new RangeError('Unsupported authenticator settings.');
  }

  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / opts.period)));
  const digest = createHmac(opts.algorithm.toLowerCase(), seed).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;

  return (binary % (10 ** opts.digits)).toString().padStart(opts.digits, '0');
}

export function currentCode(
  parsed: ParsedSeed,
  nowMs: number,
): { code: string; expiresInSeconds: number; waitMs: number } {
  if (!Number.isFinite(nowMs) || nowMs < 0 || nowMs > Number.MAX_SAFE_INTEGER) {
    throw new RangeError('Invalid authenticator time.');
  }

  const periodMs = parsed.period * 1000;
  const windowStartMs = Math.floor(nowMs / periodMs) * periodMs;
  const remainingMs = periodMs - (nowMs - windowStartMs);
  const waitMs = remainingMs < 5000 ? remainingMs : 0;
  const codeTimeMs = waitMs > 0 ? windowStartMs + periodMs : windowStartMs;

  return {
    code: totpAt(parsed.seed, codeTimeMs / 1000, parsed),
    expiresInSeconds: waitMs > 0 ? parsed.period : Math.floor(remainingMs / 1000),
    waitMs,
  };
}
