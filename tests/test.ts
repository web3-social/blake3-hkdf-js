import * as blake3 from '../src/index';
import { describe } from 'mocha';
import { assert } from 'chai';

describe('BLAKE3', () => {
    it('hash length', () => {
        const hash = blake3.hash('foo');
        assert(hash.length === 32, 'hash length is 32 bytes');
    });

    it('accumulate update', () => {
        const hash = blake3.hash('foobarbaz');

        const hasher = new blake3.Blake3();
        hasher.update('foo');
        hasher.update('bar');
        hasher.update('baz');

        assert(hasher.finalize().toString('hex') === hash.toString('hex'), 'hash is same');
    });

    it('reset as new', () => {
        const hasher = new blake3.Blake3();
        hasher.update('foo');
        hasher.update('bar');
        hasher.update('baz');
        const hash1 = hasher.finalize();
        hasher.reset();

        hasher.update('foo');
        hasher.update('bar');
        hasher.update('baz');

        assert(hasher.finalize().toString('hex') === hash1.toString('hex'), 'hash is same');
    });

    it('cannot use after free', () => {
        const hasher = new blake3.Blake3();
        hasher.free();

        assert.throws(() => {
            hasher.update('foo');
        });
    });
});

describe('HKDF-BLAKE3', () => {
    it('derive key', () => {
        const length = 32;
        const ikm = '000102030405060708090a0b0c0d0e0f';
        const salt = '000102030405060708090a0b0c0d0e0f';
        const key = blake3.hkdf(length, ikm, salt);
        assert(key.length === length, 'key length is 32 bytes');
    });

    it('invalid length', () => {
        const length = 32 * 256;
        const ikm = '000102030405060708090a0b0c0d0e0f';
        const salt = '000102030405060708090a0b0c0d0e0f';
        assert.throws(() => {
            blake3.hkdf(length, ikm, salt);
        });
    });
});
