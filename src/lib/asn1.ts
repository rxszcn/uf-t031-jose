import type * as types from '../types.d.ts'
import { invalidKeyInput, isCryptoKey, isKeyObject, validateExtractableOption } from './key.js'
import { concat, encodeBase64, decodeBase64 } from './buffer_utils.js'
import { JOSENotSupported } from '../util/errors.js'
import { keyAlgorithm, unsupportedAlg, algArgument } from './key_algorithm.js'
import type { KeyImportOptions } from '../key/import.js'

/**
 * Formats a base64 string as a PEM-encoded key with proper line breaks and headers.
 *
 * @param b64 - Base64-encoded key data
 * @param descriptor - Key type descriptor (e.g., "PUBLIC KEY", "PRIVATE KEY")
 *
 * @returns PEM-formatted string
 */
// RFC 7468, Sections 2, 10, and 13: base64 textual encodings, 64-character lines,
// PRIVATE KEY for PrivateKeyInfo and PUBLIC KEY for SubjectPublicKeyInfo.
const formatPEM = (b64: string, descriptor: string) => {
  const newlined = (b64.match(/.{1,64}/g) || []).join('\n')
  return `-----BEGIN ${descriptor}-----\n${newlined}\n-----END ${descriptor}-----`
}

interface ExportOptions {
  format: 'pem'
  type: 'spki' | 'pkcs8'
}

interface ExtractableKeyObject extends types.KeyObject {
  export(arg: ExportOptions): string
}

const genericExport = async (
  keyType: 'private' | 'public',
  keyFormat: 'spki' | 'pkcs8',
  key: unknown,
) => {
  if (isKeyObject(key)) {
    if (key.type !== keyType) {
      throw new TypeError(`key is not a ${keyType} key`)
    }

    return (key as ExtractableKeyObject).export({ format: 'pem', type: keyFormat })
  }

  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, 'CryptoKey', 'KeyObject'))
  }

  if (!key.extractable) {
    throw new TypeError('CryptoKey is not extractable')
  }

  if (key.type !== keyType) {
    throw new TypeError(`key is not a ${keyType} key`)
  }

  return formatPEM(
    encodeBase64(new Uint8Array(await crypto.subtle.exportKey(keyFormat, key))),
    `${keyType.toUpperCase()} KEY`,
  )
}

export const toSPKI = (key: unknown): Promise<string> => genericExport('public', 'spki', key)

export const toPKCS8 = (key: unknown): Promise<string> => genericExport('private', 'pkcs8', key)

/** Helper function to compare two byte arrays for equality */
const bytesEqual = (a: Uint8Array, b: Uint8Array | readonly number[]): boolean => {
  if (a.byteLength !== b.length) return false
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/** ASN.1 DER parsing state */
interface ASN1State {
  readonly data: Uint8Array
  pos: number
}

/** Creates ASN.1 parsing state */
const createASN1State = (data: Uint8Array): ASN1State => ({ data, pos: 0 })

/** Reads the byte at the current position, failing fast when the input is truncated */
const readByte = (state: ASN1State): number => {
  const byte = state.data[state.pos++]
  if (byte === undefined) {
    throw new Error('Unexpected end of ASN.1 input')
  }
  return byte
}

/** Parses ASN.1 length encoding (both short and long form) */
const parseLength = (state: ASN1State): number => {
  const first = readByte(state)
  if (first & 0x80) {
    // Long form: first byte indicates number of subsequent length bytes
    const lengthOfLen = first & 0x7f
    let length = 0
    for (let i = 0; i < lengthOfLen; i++) {
      length = (length << 8) | readByte(state)
    }
    return length
  }
  // Short form: length is encoded directly in first byte
  return first
}

/** Skips ASN.1 elements (tag + length + content) */
const skipElement = (state: ASN1State, count: number = 1): void => {
  while (count-- > 0) {
    state.pos++ // Skip tag byte
    const length = parseLength(state)
    state.pos += length // Skip content bytes
  }
}

/** Expects a specific tag and throws if not found */
const expectTag = (state: ASN1State, expectedTag: number, errorMessage: string): void => {
  if (readByte(state) !== expectedTag) {
    throw new Error(errorMessage)
  }
}

/** Gets a subarray from current position */
const getSubarray = (state: ASN1State, length: number): Uint8Array => {
  if (length < 0 || state.pos + length > state.data.length) {
    throw new Error('Unexpected end of ASN.1 input')
  }
  const result = state.data.subarray(state.pos, state.pos + length)
  state.pos += length
  return result
}

/** Parses algorithm OID and returns the OID bytes */
const parseAlgorithmOID = (state: ASN1State): Uint8Array => {
  expectTag(state, 0x06, 'Expected algorithm OID')
  const oidLen = parseLength(state)
  return getSubarray(state, oidLen)
}

/** Parses a PKCS #8 or SPKI structure up to its algorithm identifier. */
// RFC 5208, Section 5; RFC 5280, Section 4.1.2.7: inspect AlgorithmIdentifier.
// Web Crypto importKey performs the remaining key-format validation.
function parseKeyHeader(state: ASN1State, keyFormat: 'spki' | 'pkcs8') {
  expectTag(state, 0x30, `Invalid ${keyFormat === 'spki' ? 'SPKI' : 'PKCS#8'} structure`)
  parseLength(state) // Skip outer length

  if (keyFormat === 'pkcs8') {
    // Skip version (INTEGER)
    expectTag(state, 0x02, 'Expected version field')
    const length = parseLength(state)
    state.pos += length
  }

  // Parse AlgorithmIdentifier SEQUENCE
  expectTag(state, 0x30, 'Expected algorithm identifier')
  parseLength(state)
}

/** Parses algorithm identifier and returns curve name for EC/ECDH keys */
const parseECAlgorithmIdentifier = (state: ASN1State): string => {
  const algOid = parseAlgorithmOID(state)

  // RFC 8410, Section 3: id-X25519 1.3.101.110
  if (bytesEqual(algOid, [0x2b, 0x65, 0x6e])) {
    return 'X25519'
  }

  // RFC 5480, Section 2.1.1: id-ecPublicKey and namedCurve parameters.
  if (!bytesEqual(algOid, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])) {
    throw new Error('Unsupported key algorithm')
  }

  // Parse curve parameters (should be an OID for named curves)
  expectTag(state, 0x06, 'Expected curve OID')
  const curveOidLen = parseLength(state)
  const curveOid = getSubarray(state, curveOidLen)

  if (bytesEqual(curveOid, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])) return 'P-256'
  if (bytesEqual(curveOid, [0x2b, 0x81, 0x04, 0x00, 0x22])) return 'P-384'
  if (bytesEqual(curveOid, [0x2b, 0x81, 0x04, 0x00, 0x23])) return 'P-521'

  throw new Error('Unsupported named curve')
}

/** Encodes an ASN.1 DER length octet string (short and long form, ITU-T X.690 Section 8.1.3). */
const encodeLength = (length: number): Uint8Array => {
  if (length < 0x80) return new Uint8Array([length])
  const bytes: number[] = []
  let value = length
  while (value > 0) {
    bytes.unshift(value & 0xff)
    value >>>= 8
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes])
}

/** Wraps DER content in a TLV element with the given universal tag. */
const tlv = (tag: number, content: Uint8Array): Uint8Array =>
  concat(new Uint8Array([tag]), encodeLength(content.length), content)

/** Wraps DER content in a SEQUENCE element. */
const derSequence = (...elements: Uint8Array[]): Uint8Array => tlv(0x30, concat(...elements))

/** Reads a complete TLV element, returning its tag, content and advancing the parse state. */
const parseElement = (state: ASN1State): { tag: number; content: Uint8Array } => {
  const tag = readByte(state)
  const length = parseLength(state)
  return { tag, content: getSubarray(state, length) }
}

/** Reads an element and asserts its tag. */
const expectElement = (state: ASN1State, expectedTag: number, errorMessage: string): Uint8Array => {
  const { tag, content } = parseElement(state)
  if (tag !== expectedTag) {
    throw new Error(errorMessage)
  }
  return content
}

// RFC 5280 Appendix A.1 / RFC 8410 Section 3: AlgorithmIdentifier encodings.
const OID_EC_PUBLIC_KEY = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
const OID_P256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
const OID_P384 = new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x22])
const OID_P521 = new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x23])
// RFC 8017 Appendix B: rsaEncryption { iso(1) member-body(2) us(840) rsadsi(113549) 1 1 1 }
const OID_RSA_ENCRYPTION = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
// RFC 5208 Section 5: the PrivateKeyInfo version for v1 (non-attribute) private keys.
const PKCS8_VERSION_0 = tlv(0x02, new Uint8Array([0x00]))

const algorithmIdentifier = (oid: Uint8Array, parameters?: Uint8Array): Uint8Array =>
  derSequence(tlv(0x06, oid), parameters ?? new Uint8Array())

/** Maps a SEC1 named curve OID to its JOSE curve name. */
const curveFromOID = (curveOid: Uint8Array): string => {
  if (bytesEqual(curveOid, OID_P256)) return 'P-256'
  if (bytesEqual(curveOid, OID_P384)) return 'P-384'
  if (bytesEqual(curveOid, OID_P521)) return 'P-521'
  throw new Error('Unsupported named curve')
}

/** P-256/P-384/P-521 public keys are uncompressed points of a known length (RFC 5480 2.2). */
const curveFromPoint = (point: Uint8Array): string => {
  switch (point.byteLength) {
    case 65:
      return 'P-256'
    case 97:
      return 'P-384'
    case 133:
      return 'P-521'
    default:
      throw new Error('Unsupported named curve')
  }
}

const curveOID = (crv: string): Uint8Array => {
  switch (crv) {
    case 'P-256':
      return OID_P256
    case 'P-384':
      return OID_P384
    case 'P-521':
      return OID_P521
    default:
      throw new Error('Unsupported named curve')
  }
}

/**
 * Wraps an RFC 8017 RSAPrivateKey (PKCS #1) in an RFC 5208 PrivateKeyInfo (PKCS #8) so it can be
 * handed to the Web Crypto "pkcs8" importer.
 */
const pkcs8FromRSAPrivateKey = (rsaPrivateKey: Uint8Array): Uint8Array =>
  derSequence(
    PKCS8_VERSION_0,
    algorithmIdentifier(OID_RSA_ENCRYPTION, tlv(0x05, new Uint8Array())),
    tlv(0x04, rsaPrivateKey),
  )

/**
 * Wraps an RFC 8017 RSAPublicKey (PKCS #1) in an RFC 5280 SubjectPublicKeyInfo so it can be handed
 * to the Web Crypto "spki" importer.
 */
const spkiFromRSAPublicKey = (rsaPublicKey: Uint8Array): Uint8Array =>
  derSequence(
    algorithmIdentifier(OID_RSA_ENCRYPTION, tlv(0x05, new Uint8Array())),
    // RFC 5280 Section 4.1.2.7: subjectPublicKey is a BIT STRING; the leading 0x00 byte
    // declares zero unused bits, followed by the DER encoding of the RSAPublicKey.
    tlv(0x03, concat(new Uint8Array([0x00]), rsaPublicKey)),
  )

/**
 * Wraps an RFC 5915 ECPrivateKey (SEC 1) in an RFC 5208 PrivateKeyInfo (PKCS #8). The named curve
 * comes from the SEC1 parameters field when present, otherwise from the embedded public point.
 */
const pkcs8FromECPrivateKey = (ecPrivateKey: Uint8Array): Uint8Array => {
  const state = createASN1State(ecPrivateKey)
  const sequence = expectElement(state, 0x30, 'Invalid SEC1 structure')
  const inner = createASN1State(sequence)

  // version (INTEGER), privateKey (OCTET STRING)
  expectElement(inner, 0x02, 'Expected version field')
  expectElement(inner, 0x04, 'Expected private key field')

  let crv: string | undefined
  let publicPoint: Uint8Array | undefined
  while (inner.pos < inner.data.length) {
    const { tag, content } = parseElement(inner)
    if (tag === 0xa0) {
      // RFC 5915 Section 3: parameters [0] EXPLICIT, holding the namedCurve OID
      const parameters = createASN1State(content)
      crv = curveFromOID(expectElement(parameters, 0x06, 'Expected curve OID'))
    } else if (tag === 0xa1) {
      // RFC 5915 Section 3: publicKey [1] EXPLICIT BIT STRING
      const bitString = createASN1State(content)
      const pointContent = expectElement(bitString, 0x03, 'Expected public key BIT STRING')
      if (pointContent[0] !== 0x00) {
        throw new Error('Expected unused-bits byte 0x00')
      }
      publicPoint = pointContent.subarray(1)
    }
  }

  if (crv === undefined) {
    if (!publicPoint) {
      throw new Error('SEC1 key contains neither curve parameters nor a public key')
    }
    crv = curveFromPoint(publicPoint)
  }

  return derSequence(
    PKCS8_VERSION_0,
    algorithmIdentifier(OID_EC_PUBLIC_KEY, tlv(0x06, curveOID(crv))),
    tlv(0x04, ecPrivateKey),
  )
}

/**
 * Wraps a legacy private or public key container into the SPKI / PKCS #8 structure the Web Crypto
 * importers accept, throwing {@link JOSENotSupported} (the established key-format error) on any
 * parse failure.
 */
const wrapLegacyKey = (
  keyData: Uint8Array,
  legacyFormat: 'pkcs1' | 'sec1',
  isPublic: boolean,
): Uint8Array => {
  try {
    if (legacyFormat === 'pkcs1') {
      return isPublic ? spkiFromRSAPublicKey(keyData) : pkcs8FromRSAPrivateKey(keyData)
    }
    if (isPublic) {
      throw new Error('SEC1 only defines an ECPrivateKey structure')
    }
    return pkcs8FromECPrivateKey(keyData)
  } catch (cause) {
    throw new JOSENotSupported('Invalid or unsupported key format', { cause })
  }
}

const genericImport = async (
  keyFormat: 'spki' | 'pkcs8',
  keyData: Uint8Array,
  alg: string,
  options?: KeyImportOptions,
) => {
  const extractable = validateExtractableOption(options?.extractable)
  const entry = keyAlgorithm(alg, algArgument)
  if (entry.secret) {
    unsupportedAlg(algArgument)
  }
  const isPublic = keyFormat === 'spki'

  let algorithm: { name: string; hash?: string; namedCurve?: string }
  if (entry.resolve) {
    try {
      const state = createASN1State(keyData)
      parseKeyHeader(state, keyFormat)
      algorithm = entry.resolve({ crv: parseECAlgorithmIdentifier(state) })
    } catch (cause) {
      throw new JOSENotSupported('Invalid or unsupported key format', { cause })
    }
  } else {
    algorithm = entry.subtle
  }

  return crypto.subtle.importKey(
    keyFormat,
    keyData as Uint8Array<ArrayBuffer>,
    algorithm,
    extractable ?? isPublic,
    entry.usages[isPublic ? 0 : 1],
  )
}

type PEMImportFunction = (
  pem: string,
  alg: string,
  options?: KeyImportOptions,
) => Promise<types.CryptoKey>

/** Helper function to process PEM-encoded data */
const processPEMData = (pem: string, pattern: RegExp): Uint8Array => {
  return decodeBase64(pem.replace(pattern, ''))
}

export const fromPKCS8: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g)
  return genericImport('pkcs8', keyData, alg, options)
}

export const fromSPKI: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g)
  return genericImport('spki', keyData, alg, options)
}

// RFC 7468 Section 10 labels these legacy containers strictly; they are still produced by the
// OpenSSL "rsa" and "ec" output modes and other tooling predating PKCS #8.
export const fromRSAPrivateKey: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) RSA PRIVATE KEY-----|\s)/g)
  return genericImport('pkcs8', wrapLegacyKey(keyData, 'pkcs1', false), alg, options)
}

export const fromRSAPublicKey: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) RSA PUBLIC KEY-----|\s)/g)
  return genericImport('spki', wrapLegacyKey(keyData, 'pkcs1', true), alg, options)
}

export const fromECPrivateKey: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) EC PRIVATE KEY-----|\s)/g)
  return genericImport('pkcs8', wrapLegacyKey(keyData, 'sec1', false), alg, options)
}

/**
 * Extracts the Subject Public Key Info (SPKI) from an X.509 certificate. Parses the ASN.1 DER
 * structure to locate and extract the public key portion.
 *
 * @param buf - DER-encoded X.509 certificate bytes
 *
 * @returns SPKI structure as bytes
 */
// RFC 5280, Sections 4.1.2 and 4.1.2.7: extract subjectPublicKeyInfo from TBSCertificate.
// This is key extraction, not certificate path validation (Section 6).
function spkiFromX509(buf: Uint8Array): Uint8Array {
  const state = createASN1State(buf)

  // Parse outer certificate SEQUENCE
  expectTag(state, 0x30, 'Invalid certificate structure')
  const certificateLength = parseLength(state)
  if (certificateLength < 0 || state.pos + certificateLength > state.data.length) {
    throw new Error('Unexpected end of ASN.1 input')
  }

  // Parse tbsCertificate (To Be Signed Certificate) SEQUENCE
  expectTag(state, 0x30, 'Invalid tbsCertificate structure')
  parseLength(state) // Skip tbsCertificate length

  if (buf[state.pos] === 0xa0) {
    // Optional version field present (context-specific [0])
    // Skip: version, serialNumber, signature algorithm, issuer, validity, subject
    skipElement(state, 6)
  } else {
    // No version field (defaults to v1)
    // Skip: serialNumber, signature algorithm, issuer, validity, subject
    skipElement(state, 5)
  }

  // Extract subjectPublicKeyInfo SEQUENCE
  const spkiStart = state.pos
  expectTag(state, 0x30, 'Invalid SPKI structure')
  const spkiContentLen = parseLength(state)

  // Return the complete SPKI structure (tag + length + content)
  return buf.subarray(spkiStart, spkiStart + spkiContentLen + (state.pos - spkiStart))
}

/**
 * Extracts SPKI from a PEM-encoded X.509 certificate string.
 *
 * @param x509 - PEM-encoded X.509 certificate
 *
 * @returns SPKI structure as bytes
 */
export const fromX509: PEMImportFunction = (pem, alg, options?) => {
  let spki: Uint8Array
  try {
    const certificate = processPEMData(pem, /(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g)
    spki = spkiFromX509(certificate)
  } catch (cause) {
    throw new TypeError('Failed to parse the X.509 certificate', { cause })
  }
  return genericImport('spki', spki, alg, options)
}
