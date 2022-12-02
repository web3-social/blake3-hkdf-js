import * as sys from '@web3-social/blake3-hkdf-js-sys';

const isHex = /^[0-9A-Fa-f]+$/;

const fromHex = (hex: string): Buffer => {
    hex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
    if (!isHex.test(hex)) throw new Error('Invalid hex string');
    return Buffer.from(hex, 'hex');
};

const registry =
    FinalizationRegistry == undefined ? undefined : new FinalizationRegistry((instance: sys.Blake3) => instance.free());

/**
 * BLAKE3 hasher
 */
export class Blake3 {
    private _instance?: sys.Blake3;

    /**
     * Construct a new Hasher for the regular hash function.
     *
     * @param instance You SHOULD NOT use this parameter, it is for internal use only.
     */
    constructor(instance?: sys.Blake3) {
        this._instance = instance ?? new sys.Blake3();
        if (registry != undefined) {
            registry.register(this, this._instance, this._instance);
        } else {
            console.warn('FinalizationRegistry is not supported, auto free is disabled');
        }
    }

    /**
     * Construct a new Hasher for the keyed hash function.
     *
     * This is suitable for use as a message authentication code,
     * for example to replace an HMAC instance.
     * In that use case, the constant-time equality checking provided
     * by Hash is almost always a security requirement,
     * and callers need to be careful not to compare MACs as raw bytes.
     *
     * @param key 32 bytes
     * @returns BLAKE3 keyed hasher
     * @throws Error if key is not 32 bytes
     */
    static newKeyed(key: Buffer | string): Blake3 {
        if (typeof key === 'string') key = fromHex(key);
        return new Blake3(sys.Blake3.new_keyed(key));
    }

    /**
     * Construct a new Hasher for the key derivation function.
     * The context string should be hardcoded, globally unique, and application-specific.
     *
     * Given cryptographic key material of any length and a context string of any length,
     * this function outputs a 32-byte derived subkey.
     * The context string should be hardcoded, globally unique, and application-specific.
     * A good default format for such strings is "[application] [commit timestamp] [purpose]",
     * e.g., "example.com 2019-12-25 16:18:03 session tokens v1".
     *
     * Key derivation is important when you want to use the same key in multiple algorithms or use cases.
     * Using the same key with different cryptographic algorithms is generally forbidden,
     * and deriving a separate subkey for each use case protects you from bad interactions.
     * Derived keys also mitigate the damage from one part of your application accidentally leaking its key.
     *
     * As a rare exception to that general rule, however,
     * it is possible to use derive_key itself with key material that you are already using with another algorithm.
     * You might need to do this if you’re adding features to an existing application,
     * which does not yet use key derivation internally.
     * However, you still must not share key material with algorithms that forbid key reuse entirely,
     * like a one-time pad. For more on this, see sections 6.2 and 7.8 of the BLAKE3 paper.
     *
     * Note that BLAKE3 is not a password hash, and derive_key should never be used with passwords.
     * Instead, use a dedicated password hash like Argon2.
     * Password hashes are entirely different from generic hash functions, with opposite design requirements.
     *
     * @param context
     * @returns BLAKE3 derive key hasher
     */
    static newDeriveKey(context: string): Blake3 {
        return new Blake3(sys.Blake3.new_derive_key(context));
    }

    /**
     * Add input bytes to the hash state. You can call this any number of times.
     *
     * @param input Buffer or string encoded in utf8
     */
    update(input: Buffer | string) {
        if (this._instance == undefined) throw new Error('instance is freed');
        if (typeof input === 'string') input = Buffer.from(input, 'utf8');
        this._instance.update(input);
    }

    /**
     * Finalize the hash state and return the Hash of the input.
     *
     * This method is idempotent.
     * Calling it twice will give the same result.
     * You can also add more input and finalize again.
     *
     * @returns Hash
     */
    finalize() {
        if (this._instance == undefined) throw new Error('instance is freed');
        return Buffer.from(this._instance.finalize());
    }

    /**
     * Reset the Hasher to its initial state.
     */
    reset() {
        if (this._instance == undefined) throw new Error('instance is freed');
        this._instance.reset();
    }

    /**
     * When FinalizationRegistry is not supported,
     * you can call this method to free the instance manually.
     */
    free() {
        if (this._instance == undefined) return;
        if (registry != undefined) {
            registry.unregister(this._instance);
            console.warn('auto free is enabled, you should not call free manually');
        }
        this._instance.free();
        this._instance = undefined;
    }
}

const BLAKE3 = new Blake3();

/**
 * Hash the input bytes or string.
 *
 * @param input Buffer or string encoded in utf8
 * @returns Hash
 */
export const hash = (input: Buffer | string) => {
    if (typeof input === 'string') input = Buffer.from(input, 'utf8');
    BLAKE3.update(input);
    const hash = BLAKE3.finalize();
    BLAKE3.reset();
    return Buffer.from(hash);
};

/**
 * HKDF-BLAKE3
 *
 * @param length required byte length
 * @param ikm initial keying material
 * @param salt opetional salt (recommended)
 * @param info optioanl context (safe to skip)
 * @returns derived key of length bytes
 * @throws Error if length is not valid
 */
export const hkdf = (length: number, ikm: Buffer | string, salt?: Buffer | string, info?: Buffer | string) => {
    if (typeof ikm === 'string') ikm = fromHex(ikm);
    if (typeof salt === 'string') salt = fromHex(salt);
    if (typeof info === 'string') info = fromHex(info);
    return Buffer.from(sys.hkdf(length, ikm, salt, info));
};

/**
 * HKDF-BLAKE3 extract action
 *
 * @param ikm initial keying material
 * @param salt opetional salt (recommended)
 * @returns pseudo-random key
 */
export const extract = (ikm: Buffer | string, salt?: Buffer | string) => {
    if (typeof ikm === 'string') ikm = fromHex(ikm);
    if (typeof salt === 'string') salt = fromHex(salt);
    return Buffer.from(sys.extract(ikm, salt));
};

/**
 * HKDF-BLAKE3 expand action
 *
 * @param prk pseudo-random key
 * @param length required byte length
 * @param info optioanl context (safe to skip)
 * @returns output keying
 * @throws Error if length is not valid
 */
export const expand = (prk: Buffer | string, length: number, info?: Buffer | string) => {
    if (typeof prk === 'string') prk = fromHex(prk);
    if (typeof info === 'string') info = fromHex(info);
    return Buffer.from(sys.expand(prk, length, info));
};
