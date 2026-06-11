import { describe, it, expect } from 'vitest';
import { VERSION, parseSemver, semverLt } from '../src/version.js';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

describe('VERSION', () => {
  it('equals package.json version', () => {
    expect(VERSION).toBe(pkg.version);
  });
});

describe('parseSemver', () => {
  it('parses standard versions', () => {
    expect(parseSemver('1.6.2')).toEqual([1, 6, 2]);
  });
  it('strips v prefix', () => {
    expect(parseSemver('v2.0')).toEqual([2, 0, 0]);
  });
  it('handles garbage/empty', () => {
    expect(parseSemver('')).toEqual([0, 0, 0]);
    expect(parseSemver(null)).toEqual([0, 0, 0]);
    expect(parseSemver('x')).toEqual([0, 0, 0]);
  });
});

describe('semverLt', () => {
  it('("1.6.2","2.0.0")=true', () => expect(semverLt('1.6.2','2.0.0')).toBe(true));
  it('("2.0.0","1.6.2")=false', () => expect(semverLt('2.0.0','1.6.2')).toBe(false));
  it('("1.6.2","1.6.2")=false', () => expect(semverLt('1.6.2','1.6.2')).toBe(false));
  it('("1.6.2","0.0.0")=false', () => expect(semverLt('1.6.2','0.0.0')).toBe(false));
});