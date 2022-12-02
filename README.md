[![NPM](https://nodei.co/npm/@web3-social/blake3-hkdf-js.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/@web3-social/blake3-hkdf-js/)

# About

JavaScript porting of [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) and implementation of HKDF-BLAKE3

# Installation for Node.js
Command line:
```sh
npm install @web3-social/blake3-hkdf-js --save
```
or:
```sh
yarn add @web3-social/blake3-hkdf-js
```

# Examples

```javascript
const blake3 = require('@web3-social/blake3-hkdf-js');

const hash = blake3.hash('Hello World!');
console.log(hash.toString('hex'));

// hasher
const hasher = new blake3.BLAKE3();
hasher.update('foo');
hasher.update('bar');
hasher.update('baz');
const hash2 = hasher.digest();
console.log(hash2.toString('hex'));

// hkdf
const length = 16;
const ikm = '000102030405060708090a0b0c0d0e0f';
const salt = 'random bytes';
const info = 'optioanl context';
const key = blake3.hkdf(length, ikm, salt, info);
```

# API documentation

## blake3.hash(input)
shortcut for `(new blake3.BLAKE3()).update(input).finialize()`

**Kind**: global function

**Returns**: `Buffer` - hash value

## blake3.hkdf(length, ikm, salt, info)

HKDF-BLAKE3 function

**Kind**: global function

**Returns**: `Buffer` - key derived

**Throw**: `Error` - if length is not valid

| Param | Type | Optional | Description |
| --- | --- | --- | --- |
| length | `number` | false | length of output key |
| ikm | `Buffer` \| `string` | false | input key material |
| salt | `Buffer` \| `string` | true | salt |
| info | `Buffer` \| `string` | true | optional context and application specific information |

## blake3.extract(ikm, salt)

extract function

**Kind**: global function

**Returns**: `Buffer` - pseudorandom key

| Param | Type | Optional | Description |
| --- | --- | --- | --- |
| ikm | `Buffer` \| `string` | false | input key material |
| salt | `Buffer` \| `string` | true | salt |

## blake3.expand(prk, length, info)

expand function

**Kind**: global function

**Returns**: `Buffer` - key derived

**Throw**: `Error` - if length is not valid

| Param | Type | Optional | Description |
| --- | --- | --- | --- |
| prk | `Buffer` \| `string` | false | pseudorandom key |
| length | `number` | false | length of output key |
| info | `Buffer` \| `string` | true | optional context and application specific information |


## blake3.Blake3
Hasher object

### constructor blake3.Blake3()
Construct a new Hasher for the regular hash function.

### blake3.Blake3.newKeyed(key)
Construct a new Hasher for the keyed hash function.

This is suitable for use as a message authentication code, for example to replace an HMAC instance. In that use case, the constant-time equality checking provided by Hash is almost always a security requirement, and callers need to be careful not to compare MACs as raw bytes.

**Kind**: static function

**Returns**: `Blake3` - keyed hasher

**Throw**: `Error` - if key is not 32 bytes

| Param | Type | Optional | Description |
| --- | --- | --- | --- |
| key | `Buffer` \| `string` | false | key |

### blake3.Blake3.newDeriveKey(context)
Construct a new Hasher for the key derivation function. See derive_key.

Given cryptographic key material of any length and a context string of any length, this function outputs a 32-byte derived subkey. The context string should be **hardcoded, globally unique, and application-specific**. A good default format for such strings is `"[application] [commit timestamp] [purpose]"`, e.g., `"example.com 2019-12-25 16:18:03 session tokens v1"`.

Key derivation is important when you want to use the same key in multiple algorithms or use cases. Using the same key with different cryptographic algorithms is generally forbidden, and deriving a separate subkey for each use case protects you from bad interactions. Derived keys also mitigate the damage from one part of your application accidentally leaking its key.

As a rare exception to that general rule, however, it is possible to use `derive_key` itself with key material that you are already using with another algorithm. You might need to do this if you’re adding features to an existing application, which does not yet use key derivation internally. However, you still must not share key material with algorithms that forbid key reuse entirely, like a one-time pad. For more on this, see sections 6.2 and 7.8 of the [BLAKE3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).

Note that BLAKE3 is not a password hash, and **derive_key should never be used with passwords**. Instead, use a dedicated password hash like Argon2. Password hashes are entirely different from generic hash functions, with opposite design requirements.

**Kind**: static function

**Returns**: `Blake3` - derive key hasher

**Throw**: `Error` - if hasher is freed

| Param | Type | Optional | Description |
| --- | --- | --- | --- |
| context | `string` | false | context |

### blake3.Blake3#update(input)
Add input bytes to the hash state. You can call this any number of times.

**Kind**: member function

| Param | Type | Optional | Description |
| --- | --- | --- | --- |
| input | `Buffer` \| `string` | false | input |

Note: string will be converted to Buffer with `Buffer.from(input, "utf8")`

### blake3.Blake3#finialize()
Finalize the hash state and return the Hash of the input.

This method is idempotent. Calling it twice will give the same result. You can also add more input and finalize again.

**Kind**: member function

**Returns**: `Buffer` - hash value

**Throw**: `Error` - if hasher is freed


### blake3.Blake3#reset()
Reset the Hasher to its initial state.

This is functionally the same as overwriting the Hasher with a new one, using the same key or context string if any.

**Kind**: member function

**Throw**: `Error` - if hasher is freed

### blake3.Blake3#free()
Free the hasher manually.
You should not call this unless your plaform does not support [`FinalizationRegistry`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/FinalizationRegistry).

Any call to hasher after `free` will throw an error.

**Kind**: member function
