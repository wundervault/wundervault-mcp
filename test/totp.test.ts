import { describe, expect, it } from 'vitest';
import { currentCode, parseSeed, totpAt } from '../src/totp.js';

const BASE32_SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const ASCII_SEED = '12345678901234567890';

const seeds = {
  SHA1: Buffer.from(ASCII_SEED, 'ascii'),
  SHA256: Buffer.from('12345678901234567890123456789012', 'ascii'),
  SHA512: Buffer.from(
    '1234567890123456789012345678901234567890123456789012345678901234',
    'ascii',
  ),
};

const vectors = [
  { time: 59, SHA1: '94287082', SHA256: '46119246', SHA512: '90693936' },
  { time: 1111111109, SHA1: '07081804', SHA256: '68084774', SHA512: '25091201' },
  { time: 1111111111, SHA1: '14050471', SHA256: '67062674', SHA512: '99943326' },
  { time: 1234567890, SHA1: '89005924', SHA256: '91819424', SHA512: '93441116' },
  { time: 2000000000, SHA1: '69279037', SHA256: '90698825', SHA512: '38618901' },
  { time: 20000000000, SHA1: '65353130', SHA256: '77737706', SHA512: '47863826' },
];

function parsedSeed(input: string) {
  const parsed = parseSeed(input);
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) {
    throw new Error('Expected a valid test seed.');
  }
  return parsed;
}

describe('totpAt', () => {
  for (const algorithm of ['SHA1', 'SHA256', 'SHA512'] as const) {
    describe(algorithm, () => {
      for (const vector of vectors) {
        it(`matches RFC 6238 Appendix B at ${vector.time}`, () => {
          expect(totpAt(seeds[algorithm], vector.time, {
            digits: 8,
            period: 30,
            algorithm,
          })).toBe(vector[algorithm]);
        });

        it(`returns the six-digit truncation at ${vector.time}`, () => {
          expect(totpAt(seeds[algorithm], vector.time, {
            digits: 6,
            period: 30,
            algorithm,
          })).toBe(vector[algorithm].slice(-6));
        });
      }
    });
  }

  it('uses the selected period and changes only at the window boundary', () => {
    const opts = { digits: 6, period: 60, algorithm: 'SHA1' } as const;
    expect(totpAt(seeds.SHA1, 0, opts)).toBe('755224');
    expect(totpAt(seeds.SHA1, 59.999, opts)).toBe('755224');
    expect(totpAt(seeds.SHA1, 60, opts)).toBe('287082');
  });

  it('zero-pads six-digit codes', () => {
    expect(totpAt(seeds.SHA1, 1111111109, {
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
    })).toBe('081804');
  });

  it('rejects invalid times without including secret material', () => {
    for (const time of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => totpAt(seeds.SHA1, time, {
        digits: 6,
        period: 30,
        algorithm: 'SHA1',
      })).toThrow('Invalid authenticator time.');
    }
  });
});

describe('parseSeed', () => {
  it('decodes a base32 seed with the default settings', () => {
    expect(parseSeed(BASE32_SEED)).toEqual({
      ok: true,
      seed: seeds.SHA1,
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
    });
  });

  it('ignores case, whitespace and hyphens in base32 seeds', () => {
    const input = ' \tgezd-gnbv gy3t-qojq\ngezd gnbv-gy3tqojq ';
    expect(parsedSeed(input).seed).toEqual(seeds.SHA1);
  });

  it('accepts a seed of exactly ten bytes', () => {
    expect(parsedSeed('MFRGGZDFMZTWQ2LK').seed).toEqual(
      Buffer.from('abcdefghij', 'ascii'),
    );
  });

  it('accepts canonical padded and unpadded seeds', () => {
    const expected = Buffer.from(`${ASCII_SEED}1`, 'ascii');
    expect(parsedSeed(`${BASE32_SEED}GE`).seed).toEqual(expected);
    expect(parsedSeed(`${BASE32_SEED}GE======`).seed).toEqual(expected);
  });

  it('accepts an authenticator URI with default settings and an issuer', () => {
    expect(parseSeed(
      `otpauth://totp/Example%3Aalice?secret=${BASE32_SEED}&issuer=Example`,
    )).toEqual({
      ok: true,
      seed: seeds.SHA1,
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
    });
  });

  it('reads explicit URI settings and decodes the secret parameter', () => {
    expect(parseSeed(
      `otpauth://totp/Example?secret=${BASE32_SEED}GE%3D%3D%3D%3D%3D%3D` +
      '&digits=8&period=60&algorithm=SHA512',
    )).toEqual({
      ok: true,
      seed: Buffer.from(`${ASCII_SEED}1`, 'ascii'),
      digits: 8,
      period: 60,
      algorithm: 'SHA512',
    });
  });

  for (const algorithm of ['SHA1', 'SHA256', 'SHA512'] as const) {
    it(`accepts the ${algorithm} URI algorithm case-insensitively`, () => {
      const parsed = parsedSeed(
        `otpauth://totp/Example?secret=${BASE32_SEED}` +
        `&digits=6&period=30&algorithm=${algorithm.toLowerCase()}`,
      );
      expect(parsed.algorithm).toBe(algorithm);
      expect(parsed.digits).toBe(6);
      expect(parsed.period).toBe(30);
    });
  }

  const rejections = [
    { name: 'an empty seed', input: '' },
    { name: 'invalid base32 characters', input: `${BASE32_SEED}!` },
    { name: 'non-base32 digits', input: `${BASE32_SEED}0189` },
    { name: 'a short seed', input: 'JBSWY3DP' },
    { name: 'an impossible base32 length', input: `${BASE32_SEED}G` },
    { name: 'incorrect padding', input: `${BASE32_SEED}GE=====` },
    { name: 'unnecessary padding', input: `${BASE32_SEED}=` },
    { name: 'interior padding', input: `${BASE32_SEED.slice(0, 16)}=${BASE32_SEED.slice(16)}` },
    { name: 'hotp', input: `otpauth://hotp/Example?secret=${BASE32_SEED}` },
    { name: 'another URI scheme', input: `https://totp/Example?secret=${BASE32_SEED}` },
    { name: 'a malformed URI', input: `otpauth://[?secret=${BASE32_SEED}` },
    { name: 'URI credentials', input: `otpauth://user@totp/Example?secret=${BASE32_SEED}` },
    { name: 'a URI port', input: `otpauth://totp:123/Example?secret=${BASE32_SEED}` },
    { name: 'a URI fragment', input: `otpauth://totp/Example?secret=${BASE32_SEED}#fragment` },
    { name: 'a missing secret', input: 'otpauth://totp/Example?digits=6' },
    { name: 'an empty secret', input: 'otpauth://totp/Example?secret=' },
    { name: 'seven digits', input: `otpauth://totp/Example?secret=${BASE32_SEED}&digits=7` },
    { name: 'an empty digit setting', input: `otpauth://totp/Example?secret=${BASE32_SEED}&digits=` },
    { name: 'a 45-second period', input: `otpauth://totp/Example?secret=${BASE32_SEED}&period=45` },
    { name: 'an empty period', input: `otpauth://totp/Example?secret=${BASE32_SEED}&period=` },
    { name: 'MD5', input: `otpauth://totp/Example?secret=${BASE32_SEED}&algorithm=MD5` },
    { name: 'an empty algorithm', input: `otpauth://totp/Example?secret=${BASE32_SEED}&algorithm=` },
    {
      name: 'duplicate secrets',
      input: `otpauth://totp/Example?secret=${BASE32_SEED}&secret=${BASE32_SEED}`,
    },
    {
      name: 'duplicate digit settings',
      input: `otpauth://totp/Example?secret=${BASE32_SEED}&digits=6&digits=8`,
    },
    {
      name: 'duplicate period settings',
      input: `otpauth://totp/Example?secret=${BASE32_SEED}&period=30&period=60`,
    },
    {
      name: 'duplicate algorithms',
      input: `otpauth://totp/Example?secret=${BASE32_SEED}&algorithm=SHA1&algorithm=SHA256`,
    },
  ];

  for (const rejection of rejections) {
    it(`rejects ${rejection.name} without exposing the seed`, () => {
      const result = parseSeed(rejection.input);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('Expected an invalid test seed.');
      }
      expect(result.reason.length).toBeGreaterThan(0);
      expect(result.reason).not.toContain(BASE32_SEED);
      expect(result.reason).not.toContain(BASE32_SEED.toLowerCase());
      expect(result.reason).not.toContain(ASCII_SEED);
      if (rejection.input !== '') {
        expect(result.reason).not.toContain(rejection.input);
      }
      expect(Object.keys(result).sort()).toEqual(['ok', 'reason']);
    });
  }

  it('does not interpolate an unrecognized parameter value into a reason', () => {
    for (const name of ['digits', 'period', 'algorithm']) {
      const result = parseSeed(
        `otpauth://totp/Example?secret=${BASE32_SEED}&${name}=${BASE32_SEED}`,
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('Expected an invalid test setting.');
      }
      expect(result.reason).not.toContain(BASE32_SEED);
      expect(result.reason).not.toContain(ASCII_SEED);
    }
  });
});

describe('currentCode', () => {
  const parsed = parsedSeed(BASE32_SEED);

  it('returns the current code at the start of a window', () => {
    expect(currentCode(parsed, 0)).toEqual({
      code: '755224',
      expiresInSeconds: 30,
      waitMs: 0,
    });
  });

  it('returns the current code when exactly five seconds remain', () => {
    expect(currentCode(parsed, 25000)).toEqual({
      code: '755224',
      expiresInSeconds: 5,
      waitMs: 0,
    });
  });

  it('reports whole seconds left, rounded down', () => {
    const result = currentCode(parsed, 24001);
    expect(result.code).toBe('755224');
    expect(result.expiresInSeconds).toBe(5);
    expect(result.waitMs).toBe(0);
  });

  for (const nowMs of [25001, 25999, 26000, 29999]) {
    it(`selects the next window and reports the required wait at ${nowMs} ms`, () => {
      const result = currentCode(parsed, nowMs);
      expect(result).toEqual({
        code: '287082',
        expiresInSeconds: 30,
        waitMs: 30000 - nowMs,
      });
      expect(result.waitMs).toBeGreaterThan(0);
      expect(result.waitMs).toBeLessThan(5000);
      expect(result.code).toBe(totpAt(parsed.seed, (nowMs + result.waitMs) / 1000, parsed));
    });
  }

  it('returns the now-current code without waiting at the next window boundary', () => {
    expect(currentCode(parsed, 30000)).toEqual({
      code: '287082',
      expiresInSeconds: 30,
      waitMs: 0,
    });
  });

  it('uses the same strict boundary with a sixty-second period', () => {
    const sixtySecondSeed = parsedSeed(
      `otpauth://totp/Example?secret=${BASE32_SEED}&digits=8&period=60&algorithm=SHA256`,
    );

    expect(currentCode(sixtySecondSeed, 55000)).toEqual({
      code: totpAt(sixtySecondSeed.seed, 0, sixtySecondSeed),
      expiresInSeconds: 5,
      waitMs: 0,
    });
    expect(currentCode(sixtySecondSeed, 55001)).toEqual({
      code: totpAt(sixtySecondSeed.seed, 60, sixtySecondSeed),
      expiresInSeconds: 60,
      waitMs: 4999,
    });
    expect(currentCode(sixtySecondSeed, 60000)).toEqual({
      code: totpAt(sixtySecondSeed.seed, 60, sixtySecondSeed),
      expiresInSeconds: 60,
      waitMs: 0,
    });
  });

  it('rejects invalid clocks with a fixed error message', () => {
    for (const nowMs of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => currentCode(parsed, nowMs)).toThrow('Invalid authenticator time.');
    }
  });
});

describe('lenient seed forms (owner pastes what the service shows)', () => {
  it('accepts a seed whose leftover bits are not zero, giving the same codes as the canonical form', () => {
    const canonical = parseSeed('GEZDGNBVGY3TQOJQ');           // 10 bytes, no leftover bits
    expect(canonical.ok).toBe(true);
    const odd = parseSeed('GEZDGNBVGY3TQOJQGF');                // 11 bytes + 2 leftover bits set
    expect(odd.ok).toBe(true);
  });
  it('accepts an otpauth URI with no label', () => {
    const r = parseSeed('otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(r.ok).toBe(true);
  });
});
