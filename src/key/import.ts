/**
 * Cryptographic key import functions
 *
 * @module
 *
 * @see {@link https://www.rfc-editor.org/info/rfc7468/#section-10 RFC 7468, Section 10: PKCS #8}
 * @see {@link https://www.rfc-editor.org/info/rfc7468/#section-13 RFC 7468, Section 13: SubjectPublicKeyInfo}
 */

import { decode as decodeBase64URL } from '../util/base64url.js'
import {
  fromSPKI,
  fromPKCS8,
  fromX509,
  fromRSAPrivateKey,
  fromRSAPublicKey,
  fromECPrivateKey,
} from '../lib/asn1.js'
import { jwkToKey, validateExtractableOption, normalizeJwk } from '../lib/key.js'
import { keyAlgorithm } from '../lib/key_algorithm.js'
import { JOSENotSupported } from '../util/errors.js'
import { isObject } from '../lib/validate.js'

import type * as types from '../types.d.ts'

/**
 * Maps a JWK key type to the value returned by {@link importJWK}. An "oct" JWK returns
 * {@link !Uint8Array}; other supported key types return {@link types.CryptoKey CryptoKey}. A JWK
 * whose "kty" is not statically known resolves to their union.
 */
export type ImportedJWK<JWKType extends types.JWK> = JWKType extends { kty: 'oct' }
  ? Uint8Array
  : JWKType extends { kty: 'AKP' | 'EC' | 'OKP' | 'RSA' }
    ? types.CryptoKey
    : types.CryptoKey | Uint8Array

/** Key import options. */
export interface KeyImportOptions {
  /**
   * Whether the imported CryptoKey is extractable. Overrides JWK "ext" when set. Without either,
   * defaults to false for private keys, true otherwise.
   */
  extractable?: boolean
}

/**
 * Imports a PEM-encoded SPKI string as a {@link !CryptoKey}.
 *
 * > [!NOTE]\
 * > For RSA keys, use the rsaEncryption OID (1.2.840.113549.1.1.1). The id-RSASSA-PSS OID
 * > (1.2.840.113549.1.1.10) is not supported by the Web Cryptography API.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const algorithm = 'ES256'
 * const spki = `-----BEGIN PUBLIC KEY-----
 * MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFlHHWfLk0gLBbsLTcuCrbCqoHqmM
 * YJepMC+Q+Dd6RBmBiA41evUsNMwLeN+PNFqib+xwi9JkJ8qhZkq8Y/IzGg==
 * -----END PUBLIC KEY-----`
 * const ecPublicKey = await jose.importSPKI(spki, algorithm)
 * ```
 *
 * @param spki PEM-encoded SPKI string
 * @param alg JSON Web Algorithm identifier to be used with the imported key. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importSPKI(
  spki: string,
  alg: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey> {
  if (typeof spki !== 'string' || spki.indexOf('-----BEGIN PUBLIC KEY-----') !== 0) {
    throw new TypeError('"spki" must be SPKI formatted string')
  }
  return fromSPKI(spki, alg, options)
}

/**
 * Imports a PEM-encoded X.509 certificate's public key as a {@link !CryptoKey}.
 *
 * > [!NOTE]\
 * > For RSA keys, use the rsaEncryption OID (1.2.840.113549.1.1.1). The id-RSASSA-PSS OID
 * > (1.2.840.113549.1.1.10) is not supported by the Web Cryptography API.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const algorithm = 'ES256'
 * const x509 = `-----BEGIN CERTIFICATE-----
 * MIIBXjCCAQSgAwIBAgIGAXvykuMKMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMK3Np
 * QXBNOXpBdk1VaXhXVWVGaGtjZXg1NjJRRzFyQUhXaV96UlFQTVpQaG8wHhcNMjEw
 * OTE3MDcwNTE3WhcNMjIwNzE0MDcwNTE3WjA2MTQwMgYDVQQDDCtzaUFwTTl6QXZN
 * VWl4V1VlRmhrY2V4NTYyUUcxckFIV2lfelJRUE1aUGhvMFkwEwYHKoZIzj0CAQYI
 * KoZIzj0DAQcDQgAE8PbPvCv5D5xBFHEZlBp/q5OEUymq7RIgWIi7tkl9aGSpYE35
 * UH+kBKDnphJO3odpPZ5gvgKs2nwRWcrDnUjYLDAKBggqhkjOPQQDAgNIADBFAiEA
 * 1yyMTRe66MhEXID9+uVub7woMkNYd0LhSHwKSPMUUTkCIFQGsfm1ecXOpeGOufAh
 * v+A1QWZMuTWqYt+uh/YSRNDn
 * -----END CERTIFICATE-----`
 * const ecPublicKey = await jose.importX509(x509, algorithm)
 * ```
 *
 * @param x509 X.509 certificate string
 * @param alg JSON Web Algorithm identifier to be used with the imported key. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importX509(
  x509: string,
  alg: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey> {
  if (typeof x509 !== 'string' || x509.indexOf('-----BEGIN CERTIFICATE-----') !== 0) {
    throw new TypeError('"x509" must be X.509 formatted string')
  }
  return fromX509(x509, alg, options)
}

/**
 * Imports a PEM-encoded PKCS #8 string as a {@link !CryptoKey}.
 *
 * > [!NOTE]\
 * > For RSA keys, use the rsaEncryption OID (1.2.840.113549.1.1.1). The id-RSASSA-PSS OID
 * > (1.2.840.113549.1.1.10) is not supported by the Web Cryptography API.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const algorithm = 'ES256'
 * const pkcs8 = `-----BEGIN PRIVATE KEY-----
 * MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiyvo0X+VQ0yIrOaN
 * nlrnUclopnvuuMfoc8HHly3505OhRANCAAQWUcdZ8uTSAsFuwtNy4KtsKqgeqYxg
 * l6kwL5D4N3pEGYGIDjV69Sw0zAt43480WqJv7HCL0mQnyqFmSrxj8jMa
 * -----END PRIVATE KEY-----`
 * const ecPrivateKey = await jose.importPKCS8(pkcs8, algorithm)
 * ```
 *
 * @param pkcs8 PEM-encoded PKCS #8 string
 * @param alg JSON Web Algorithm identifier to be used with the imported key. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importPKCS8(
  pkcs8: string,
  alg: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey> {
  if (typeof pkcs8 !== 'string' || pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0) {
    throw new TypeError('"pkcs8" must be PKCS#8 formatted string')
  }
  return fromPKCS8(pkcs8, alg, options)
}

/**
 * Imports a PEM-encoded PKCS #1 RSA private key as a {@link !CryptoKey}. The legacy RSAPrivateKey
 * structure is wrapped in a PKCS #8 PrivateKeyInfo before being imported via the system key import
 * path.
 *
 * > [!NOTE]\
 * > For RSA keys, use the rsaEncryption OID (1.2.840.113549.1.1.1). The id-RSASSA-PSS OID
 * > (1.2.840.113549.1.1.10) is not supported by the Web Cryptography API.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const pkcs1 = `-----BEGIN RSA PRIVATE KEY-----
 * MIIEpAIBAAKCAQEA...
 * -----END RSA PRIVATE KEY-----`
 * const rsaPrivateKey = await jose.importRSAPrivateKey(pkcs1, 'PS256')
 * ```
 *
 * @param pkcs1 PEM-encoded PKCS #1 RSA private key string (`-----BEGIN RSA PRIVATE KEY-----`)
 * @param alg JSON Web Algorithm identifier to be used with the imported key. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importRSAPrivateKey(
  pkcs1: string,
  alg: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey> {
  if (typeof pkcs1 !== 'string' || pkcs1.indexOf('-----BEGIN RSA PRIVATE KEY-----') !== 0) {
    throw new TypeError('"pkcs1" must be PKCS#1 formatted string')
  }
  return fromRSAPrivateKey(pkcs1, alg, options)
}

/**
 * Imports a PEM-encoded PKCS #1 RSA public key as a {@link !CryptoKey}. The legacy RSAPublicKey
 * structure is wrapped in a SubjectPublicKeyInfo before being imported via the system key import
 * path.
 *
 * > [!NOTE]\
 * > For RSA keys, use the rsaEncryption OID (1.2.840.113549.1.1.1). The id-RSASSA-PSS OID
 * > (1.2.840.113549.1.1.10) is not supported by the Web Cryptography API.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const pkcs1 = `-----BEGIN RSA PUBLIC KEY-----
 * MIIBCgKCAQEA...
 * -----END RSA PUBLIC KEY-----`
 * const rsaPublicKey = await jose.importRSAPublicKey(pkcs1, 'RS256')
 * ```
 *
 * @param pkcs1 PEM-encoded PKCS #1 RSA public key string (`-----BEGIN RSA PUBLIC KEY-----`)
 * @param alg JSON Web Algorithm identifier to be used with the imported key. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importRSAPublicKey(
  pkcs1: string,
  alg: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey> {
  if (typeof pkcs1 !== 'string' || pkcs1.indexOf('-----BEGIN RSA PUBLIC KEY-----') !== 0) {
    throw new TypeError('"pkcs1" must be PKCS#1 formatted string')
  }
  return fromRSAPublicKey(pkcs1, alg, options)
}

/**
 * Imports a PEM-encoded SEC 1 EC private key as a {@link !CryptoKey}. The legacy ECPrivateKey
 * structure is wrapped in a PKCS #8 PrivateKeyInfo before being imported via the system key import
 * path.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const sec1 = `-----BEGIN EC PRIVATE KEY-----
 * MHcCAQEE...
 * -----END EC PRIVATE KEY-----`
 * const ecPrivateKey = await jose.importECPrivateKey(sec1, 'ES256')
 * ```
 *
 * @param sec1 PEM-encoded SEC 1 EC private key string (`-----BEGIN EC PRIVATE KEY-----`)
 * @param alg JSON Web Algorithm identifier to be used with the imported key. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importECPrivateKey(
  sec1: string,
  alg: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey> {
  if (typeof sec1 !== 'string' || sec1.indexOf('-----BEGIN EC PRIVATE KEY-----') !== 0) {
    throw new TypeError('"sec1" must be SEC1 formatted string')
  }
  return fromECPrivateKey(sec1, alg, options)
}

/**
 * Imports a JWK as a {@link !CryptoKey} or {@link !Uint8Array}. Asymmetric imports require either the
 * "alg" argument or JWK "alg" parameter. For AKP keys, the JWK "alg" parameter is required and must
 * match the argument when provided.
 *
 * > [!NOTE]\
 * > CryptoKey imports honor the JWK "key_ops" and "ext" parameters.
 *
 * > [!NOTE]\
 * > Symmetric JWKs (`kty: "oct"`) return {@link !Uint8Array} instead of CryptoKey.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const ecPublicKey = await jose.importJWK(
 *   {
 *     crv: 'P-256',
 *     kty: 'EC',
 *     x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
 *     y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo',
 *   },
 *   'ES256',
 * )
 *
 * const rsaPublicKey = await jose.importJWK(
 *   {
 *     kty: 'RSA',
 *     e: 'AQAB',
 *     n: '12oBZRhCiZFJLcPg59LkZZ9mdhSMTKAQZYq32k_ti5SBB6jerkh-WzOMAO664r_qyLkqHUSp3u5SbXtseZEpN3XPWGKSxjsy-1JyEFTdLSYe6f9gfrmxkUF_7DTpq0gn6rntP05g2-wFW50YO7mosfdslfrTJYWHFhJALabAeYirYD7-9kqq9ebfFMF4sRRELbv9oi36As6Q9B3Qb5_C1rAzqfao_PCsf9EPsTZsVVVkA5qoIAr47lo1ipfiBPxUCCNSdvkmDTYgvvRm6ZoMjFbvOtgyts55fXKdMWv7I9HMD5HwE9uW839PWA514qhbcIsXEYSFMPMV6fnlsiZvQQ',
 *   },
 *   'PS256',
 * )
 * ```
 *
 * @param jwk JSON Web Key.
 * @param alg JSON Web Algorithm identifier to be used with the imported key. Default is the "alg"
 *   property on the JWK. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export function importJWK<JWKType extends types.JWK>(
  jwk: JWKType,
  alg?: string,
  options?: KeyImportOptions,
): Promise<ImportedJWK<JWKType>>
export async function importJWK(
  jwk: types.JWK,
  alg?: string,
  options?: KeyImportOptions,
): Promise<types.CryptoKey | Uint8Array> {
  if (!isObject(jwk)) {
    throw new TypeError('JWK must be an object')
  }
  const normalized = normalizeJwk(jwk)
  const extractable = validateExtractableOption(options?.extractable)

  const { alg: jwkAlg } = normalized
  alg ??= jwkAlg

  if (normalized.kty !== 'oct' && !alg) {
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present')
  }

  switch (normalized.kty) {
    // RFC 7518, Section 6.4.1: decode the symmetric Key Value.
    case 'oct':
      if (typeof normalized.k !== 'string') {
        throw new TypeError('missing "k" (Key Value) Parameter value')
      }

      return decodeBase64URL(normalized.k)
    // RFC 9964, Section 3: AKP requires the alg Parameter.
    case 'AKP': {
      if (typeof jwkAlg !== 'string' || !jwkAlg) {
        throw new TypeError('missing "alg" (Algorithm) Parameter value')
      }
      if (alg !== jwkAlg) {
        throw new TypeError('JWK alg and alg option value mismatch')
      }
      return jwkToKey(keyAlgorithm(alg), normalized, extractable)
    }
    case 'RSA':
    case 'EC':
    case 'OKP':
      return jwkToKey(keyAlgorithm(alg), normalized, extractable)
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value')
  }
}
