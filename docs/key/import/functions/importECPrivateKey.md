# Function: importECPrivateKey()

## [💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

▸ **importECPrivateKey**(`sec1`, `alg`, `options?`): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`CryptoKey`](https://developer.mozilla.org/docs/Web/API/CryptoKey)\>

Imports a PEM-encoded SEC 1 EC private key as a [CryptoKey](https://developer.mozilla.org/docs/Web/API/CryptoKey). The legacy ECPrivateKey
structure is wrapped in a PKCS #8 PrivateKeyInfo before being imported via the system key import
path.

This function is exported (as a named export) from the main `'jose'` module entry point as well
as from its subpath export `'jose/key/import'`.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `sec1` | `string` | PEM-encoded SEC 1 EC private key string (`-----BEGIN EC PRIVATE KEY-----`) |
| `alg` | `string` | JSON Web Algorithm identifier to be used with the imported key. See [Algorithm Key Requirements](https://github.com/panva/jose/issues/210). |
| `options?` | [`KeyImportOptions`](../interfaces/KeyImportOptions.md) | - |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`CryptoKey`](https://developer.mozilla.org/docs/Web/API/CryptoKey)\>

## Example

```js
const sec1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEE...
-----END EC PRIVATE KEY-----`
const ecPrivateKey = await jose.importECPrivateKey(sec1, 'ES256')
```
