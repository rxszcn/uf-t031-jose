import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CompactSign,
  CompactEncrypt,
  compactVerify,
  compactDecrypt,
  calculateJwkThumbprint,
  exportJWK,
  importJWK,
  importPKCS8,
  importSPKI,
  importRSAPrivateKey,
  importRSAPublicKey,
  importECPrivateKey,
  errors,
} from '../../src/index.js'
import { errorLike } from '../_errors.js'
import { decodeBase64, concat, encodeBase64 } from '../../src/lib/buffer_utils.js'

// 固定 RSA 测试向量：同一 2048-bit 密钥对导出的 PKCS#1 PEM 与 JWK 参数，经 Node crypto
// 独立重新解析并签名/验签交叉验证，保证所有形式彼此自洽。
const RSA_PKCS1_PRIVATE_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3PKGEnWa0CER+hnwd8RX8YckfuhIGQAvkN+sXlwA+psb24qN
c0ag/SQdoswbuSuG9+5OwQI9FzhyqhR5cwJ52Me2HevzynvUpkiOEfwTQYrookX7
9kemvTmHLczSAafzCdiS0vi3iwO8ku8nMdQsi20XQaTcWJ77oTpDbmVSx7oPeSS8
VQMUOIiIzfU2YMh2NOSPTSc8F8Ez0NLQHnJsrbzzo4/B/cROsI6sLfpmeiXYyA4F
Z4YCn8KZPLRoUIaGXOfX1Jti84XmRjDYdBG9IOixkypOyo8i6Y4Sa8u9CiaDZq5r
U5JAj1MbN7+clvTEgNto2L9MZTm4FVuoiR2F5wIDAQABAoIBAAFwOjt6tMhkyHXq
qkVGYLE7tceBYL959kSdvsTJcri0gYo53xQLhRm+ARnSb6a5bufPmlrd1kyWAlEX
fPGz/jS685bIoGnO6uq/QZCmaIxK50Hv4nBBXKNENE5Y2dWrcnQrISqcyebYWLru
wq+Py0984nRaYhnkNEncMpcNs3cWWI6wfUZNbBxK+uQOqPR3zdFDsLzQSuM+RDTR
E6QHCJfcE+WFc2ogq9K62MlIXMFbp4zck+kWYt7h/ILppOvXjXPS5GpPtywVC8hf
/eO9Rj9bCfbkYD5dR0cSvllEQNrnGDiH5Snf02PCa/igQWvkJQpfNg5qIQFijjC3
o0GpPdECgYEA9DU3cJI6KCF0QOssknKeyYCLjoO4WnKd0ilqsxGjixSXfpRdoVmn
18r2Fy+894yIbpwoR0ErfQt4jOZ4H5MFWOhoOACrGBOEZy9btxdlSzaLfBX8jZtm
b/Jzy9bDUCur1Lf61FAbmtnSZ5x/i3yaOkcYj//WCD39+LxQD1lIMUkCgYEA553F
genqdUzsIC8Sv6MYn+FiNf2XPGVxjtB0pewvX3vj/hrHcM0R4E/eAU93dLsfs0Xh
41ffdum8Bjbw6WJolSnI6wwhsxzrozqn8abzntofRFkn6GS+RExe/7IFP29MA+1s
5ICWUOlZGvbCw7d0QFkSceupXCH3XXw15wlKLa8CgYB+V7HxCZYRAQ3WMFWFBsvj
0B9jgf40vSuteUP8lNmZsPOXx0aRnYLaf+TFpisLn6dOIngsNSk8rlyV+P6Yx0Vy
8/pHTwE1mZNclwHKPc5oFTYg4nchBA8BR9xkzx2JMq7ZhL2+bht6B8t1U2AhWDuq
fvHUPjYLWZc1wqdg6X4SEQKBgQDUyyPxdqpcuJ5b90OfY0W1ZgmoFuNCruTE1AnH
gxYHALj39Tx1C0M4Nch+pbbXPTAjsbmV+F6rTpTblNCDa1EwceJQ6KVxfMmU/sfb
gYpj0HxXfB3pKd2QvCWvf6vImwVYumKIEQeJMMoXtsw7qimZEPycQ2om5mHwtrSD
HgrTqwKBgEjDopjVuWwEPGw3VGfyujAtzs9T1nV9AHowXZf5I8a/45O31+hrLZJ4
FASCMcEamCmqhLH9wajnFlPe/d8NPTdvN5/A68p2b07gfGFvAVsZJXCvxIiEYjvp
yGlfcY6MCSqfeyxFK4ad7O6cyqiD8xtkqmcozxgKTrt+WoUZK5V6
-----END RSA PRIVATE KEY-----`

const RSA_PKCS1_PUBLIC_PEM = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3PKGEnWa0CER+hnwd8RX8YckfuhIGQAvkN+sXlwA+psb24qNc0ag
/SQdoswbuSuG9+5OwQI9FzhyqhR5cwJ52Me2HevzynvUpkiOEfwTQYrookX79kem
vTmHLczSAafzCdiS0vi3iwO8ku8nMdQsi20XQaTcWJ77oTpDbmVSx7oPeSS8VQMU
OIiIzfU2YMh2NOSPTSc8F8Ez0NLQHnJsrbzzo4/B/cROsI6sLfpmeiXYyA4FZ4YC
n8KZPLRoUIaGXOfX1Jti84XmRjDYdBG9IOixkypOyo8i6Y4Sa8u9CiaDZq5rU5JA
j1MbN7+clvTEgNto2L9MZTm4FVuoiR2F5wIDAQAB
-----END RSA PUBLIC KEY-----`

// 与上述 PEM 同一密钥对的 JWK 参数。
const RSA_N =
  '3PKGEnWa0CER-hnwd8RX8YckfuhIGQAvkN-sXlwA-psb24qNc0ag_SQdoswbuSuG9-5OwQI9FzhyqhR5cwJ52Me2HevzynvUpkiOEfwTQYrookX79kemvTmHLczSAafzCdiS0vi3iwO8ku8nMdQsi20XQaTcWJ77oTpDbmVSx7oPeSS8VQMUOIiIzfU2YMh2NOSPTSc8F8Ez0NLQHnJsrbzzo4_B_cROsI6sLfpmeiXYyA4FZ4YCn8KZPLRoUIaGXOfX1Jti84XmRjDYdBG9IOixkypOyo8i6Y4Sa8u9CiaDZq5rU5JAj1MbN7-clvTEgNto2L9MZTm4FVuoiR2F5w'
const RSA_E = 'AQAB'
const RSA_D =
  'AXA6O3q0yGTIdeqqRUZgsTu1x4Fgv3n2RJ2-xMlyuLSBijnfFAuFGb4BGdJvprlu58-aWt3WTJYCURd88bP-NLrzlsigac7q6r9BkKZojErnQe_icEFco0Q0TljZ1atydCshKpzJ5thYuu7Cr4_LT3zidFpiGeQ0Sdwylw2zdxZYjrB9Rk1sHEr65A6o9HfN0UOwvNBK4z5ENNETpAcIl9wT5YVzaiCr0rrYyUhcwVunjNyT6RZi3uH8gumk69eNc9Lkak-3LBULyF_9471GP1sJ9uRgPl1HRxK-WURA2ucYOIflKd_TY8Jr-KBBa-QlCl82DmohAWKOMLejQak90Q'

// SEC 1 (RFC 5915 ECPrivateKey) 固定向量，每条 NIST 曲线一个，PEM 与 JWK 参数一一对应。
const EC_VECTORS = [
  {
    alg: 'ES256',
    crv: 'P-256',
    pem: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBEbBO9Trt1SwlQ/NSkXw2IId4I4rcvZJ7IHMP7drKVwoAoGCCqGSM49
AwEHoUQDQgAE585fbE6aisRg3TsDJaClqJ5e4A8gFW9G2z5jXKLG5QbXQJEs5syA
oBsjbaTL+kiO0f8L4GCTOhUmh05KQpfQNQ==
-----END EC PRIVATE KEY-----`,
    d: 'ERsE71Ou3VLCVD81KRfDYgh3gjity9knsgcw_t2spXA',
    x: '585fbE6aisRg3TsDJaClqJ5e4A8gFW9G2z5jXKLG5QY',
    y: '10CRLObMgKAbI22ky_pIjtH_C-BgkzoVJodOSkKX0DU',
  },
  {
    alg: 'ES384',
    crv: 'P-384',
    pem: `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBuRhLTaK6yfShyFdSuV/eS6xbWOAFkG8jxXAAiNTu9O/G4dQKm61Ly
MX3wqi3CslGgBwYFK4EEACKhZANiAAQPHoBfFoctJRe+HCavkY6CL68qj11XXhxb
WWhYcitiv1ZfRCkmn9QyoxBaDz9NhGflXr0hzJaM2i3UfDED9z9IeOs0IyinrnYq
+P5cIrETETX0flbfouxeGDZER1FtlkM=
-----END EC PRIVATE KEY-----`,
    d: 'bkYS02iusn0ochXUrlf3kusW1jgBZBvI8VwAIjU7vTvxuHUCputS8jF98KotwrJR',
    x: 'Dx6AXxaHLSUXvhwmr5GOgi-vKo9dV14cW1loWHIrYr9WX0QpJp_UMqMQWg8_TYRn',
    y: '5V69IcyWjNot1HwxA_c_SHjrNCMop652Kvj-XCKxExE19H5W36LsXhg2REdRbZZD',
  },
  {
    alg: 'ES512',
    crv: 'P-521',
    pem: `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBJ4opVN+2KyTFX96FPmrV+WEwqmVTRgR0LJMYxNRddYUj1AiTos/p
7kFn5AIVGsnt9uPsULSya7T9NE1fZVUlKe+gBwYFK4EEACOhgYkDgYYABAGHcBDt
7VEqWsN3WgEuJXOGDLcQG8ozGFtHQS0vFS08eWTRjlWMVM2dxPS3b65Y/GhnHgE+
FFjg+Tw5UhR3UmzmYAAlVN8kDluK+QckxQj2tCA5/DZeu6iy4aPWhsa6oKJvKCOC
upUjJNO4JzeWAfq+fE865mPo6Cx+DaHHMV8S1kpwUg==
-----END EC PRIVATE KEY-----`,
    d: 'ASeKKVTftiskxV_ehT5q1flhMKplU0YEdCyTGMTUXXWFI9QIk6LP6e5BZ-QCFRrJ7fbj7FC0smu0_TRNX2VVJSnv',
    x: 'AYdwEO3tUSpaw3daAS4lc4YMtxAbyjMYW0dBLS8VLTx5ZNGOVYxUzZ3E9Ldvrlj8aGceAT4UWOD5PDlSFHdSbOZg',
    y: 'ACVU3yQOW4r5ByTFCPa0IDn8Nl67qLLho9aGxrqgom8oI4K6lSMk07gnN5YB-r58TzrmY-joLH4NoccxXxLWSnBS',
  },
] as const

test('importRSAPrivateKey imports an RFC 8017 PKCS#1 RSA private key', async () => {
  const key = await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RS256', { extractable: true })
  assert.equal(key.type, 'private')
  assert.equal(key.algorithm.name, 'RSASSA-PKCS1-v1_5')
  const jwk = await exportJWK(key)
  assert.equal(jwk.kty, 'RSA')
  assert.equal(jwk.n, RSA_N)
  assert.equal(jwk.e, RSA_E)
  assert.equal(jwk.d, RSA_D)
})

test('importRSAPublicKey imports an RFC 8017 PKCS#1 RSA public key', async () => {
  const key = await importRSAPublicKey(RSA_PKCS1_PUBLIC_PEM, 'RS256')
  assert.equal(key.type, 'public')
  assert.equal(key.algorithm.name, 'RSASSA-PKCS1-v1_5')
  assert.equal(key.extractable, true)
  const jwk = await exportJWK(key)
  assert.equal(jwk.kty, 'RSA')
  assert.equal(jwk.n, RSA_N)
  assert.equal(jwk.e, RSA_E)
  assert.equal(jwk.d, undefined)
})

test('legacy RSA imports are equivalent to JWK and SPKI/PKCS#8 imports', async () => {
  // 公钥指纹跨表示形式应一致：PKCS#1 包装导入、JWK 导入、SPKI 导入指向同一密钥。
  const legacyPub = await importRSAPublicKey(RSA_PKCS1_PUBLIC_PEM, 'PS256', { extractable: true })
  const jwkPub = await importJWK({ kty: 'RSA', n: RSA_N, e: RSA_E }, 'PS256')
  const expectedThumbprint = await calculateJwkThumbprint(await exportJWK(jwkPub))
  assert.equal(await calculateJwkThumbprint(await exportJWK(legacyPub)), expectedThumbprint)

  // 由 PKCS#1 公钥包装得到的 SPKI 必须被标准 importSPKI 接受并指向同一密钥。
  const spkiDer = new Uint8Array(await crypto.subtle.exportKey('spki', legacyPub))
  const spkiPem = `-----BEGIN PUBLIC KEY-----
${encodeBase64(spkiDer)
  .match(/.{1,64}/g)!
  .join('\n')}
-----END PUBLIC KEY-----`
  const standardPub = await importSPKI(spkiPem, 'PS256')
  assert.equal(await calculateJwkThumbprint(await exportJWK(standardPub)), expectedThumbprint)

  // 私钥导入与公钥导入构成匹配的密钥对。
  const legacyPriv = await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'PS256', {
    extractable: true,
  })
  const privJwk = await exportJWK(legacyPriv)
  assert.equal(privJwk.n, RSA_N)
  assert.equal(privJwk.d, RSA_D)
})

test('a PKCS#1 RSA key signs and verifies end to end', async () => {
  const privateKey = await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RS256')
  const publicKey = await importRSAPublicKey(RSA_PKCS1_PUBLIC_PEM, 'RS256')
  const jwt = await new CompactSign(new TextEncoder().encode('legacy-rsa'))
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey)
  const { payload } = await compactVerify(jwt, publicKey)
  assert.equal(new TextDecoder().decode(payload), 'legacy-rsa')
})

test('legacy keys work for JWE key management (RSA-OAEP and ECDH-ES)', async () => {
  // PKCS#1 RSA key pair wraps/unwrap a content encryption key.
  const rsaPriv = await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RSA-OAEP')
  const rsaPub = await importRSAPublicKey(RSA_PKCS1_PUBLIC_PEM, 'RSA-OAEP')
  const rsaJwe = await new CompactEncrypt(new TextEncoder().encode('secret'))
    .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
    .encrypt(rsaPub)
  const rsaResult = await compactDecrypt(rsaJwe, rsaPriv)
  assert.equal(new TextDecoder().decode(rsaResult.plaintext), 'secret')

  // SEC1 EC private key and its matching public point run ECDH-ES.
  const { pem, alg } = EC_VECTORS[0]!
  const ecPriv = await importECPrivateKey(pem, 'ECDH-ES')
  const ecJwk = await exportJWK(await importECPrivateKey(pem, alg, { extractable: true }))
  const ecPub = await importJWK({ kty: 'EC', crv: ecJwk.crv, x: ecJwk.x, y: ecJwk.y }, 'ECDH-ES')
  const ecJwe = await new CompactEncrypt(new TextEncoder().encode('secret'))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
    .encrypt(ecPub)
  const ecResult = await compactDecrypt(ecJwe, ecPriv)
  assert.equal(new TextDecoder().decode(ecResult.plaintext), 'secret')
})

for (const { alg, crv, pem, d, x, y } of EC_VECTORS) {
  test(`importECPrivateKey imports an RFC 5915 SEC1 ${crv} private key (${alg})`, async () => {
    const key = await importECPrivateKey(pem, alg, { extractable: true })
    assert.equal(key.type, 'private')
    assert.equal((key.algorithm as EcKeyAlgorithm).namedCurve, crv)
    const jwk = await exportJWK(key)
    assert.equal(jwk.kty, 'EC')
    assert.equal(jwk.crv, crv)
    assert.equal(jwk.d, d)
    assert.equal(jwk.x, x)
    assert.equal(jwk.y, y)
  })
}

test('a SEC1 EC key signs and verifies end to end', async () => {
  const { pem } = EC_VECTORS[0]!
  const privateKey = await importECPrivateKey(pem, 'ES256')
  // 从同一 SEC1 向量导出的 SPKI 公钥
  const jwk = await exportJWK(await importECPrivateKey(pem, 'ES256', { extractable: true }))
  const publicKey = await importJWK({ kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y }, 'ES256')
  const jwt = await new CompactSign(new TextEncoder().encode('legacy-ec'))
    .setProtectedHeader({ alg: 'ES256' })
    .sign(privateKey)
  const { payload } = await compactVerify(jwt, publicKey)
  assert.equal(new TextDecoder().decode(payload), 'legacy-ec')
})

test('SEC1 keys without the optional parameters field infer the curve from the public point', async () => {
  const { pem, alg, crv, d } = EC_VECTORS[0]!
  const der = decodeBase64(pem.replace(/(?:-----(?:BEGIN|END) EC PRIVATE KEY-----|\s)/g, ''))

  // Rebuild the ECPrivateKey SEQUENCE omitting the optional [0] parameters element (RFC 5915 3).
  let pos = 0
  assert.equal(der[pos++], 0x30)
  let outerLen = der[pos++]!
  if (outerLen & 0x80) {
    const n = outerLen & 0x7f
    outerLen = 0
    for (let i = 0; i < n; i++) outerLen = (outerLen << 8) | der[pos++]!
  }
  const end = pos + outerLen
  const kept: Uint8Array[] = []
  while (pos < end) {
    const tag = der[pos]!
    let len = der[pos + 1]!
    let header = 2
    if (len & 0x80) {
      const n = len & 0x7f
      len = 0
      for (let i = 0; i < n; i++) len = (len << 8) | der[pos + 2 + i]!
      header = 2 + n
    }
    if (tag !== 0xa0) kept.push(der.subarray(pos, pos + header + len))
    pos += header + len
  }
  const body = concat(...kept)
  const stripped = concat(new Uint8Array([0x30, body.length]), body)
  const strippedPem = `-----BEGIN EC PRIVATE KEY-----
${encodeBase64(stripped)
  .match(/.{1,64}/g)!
  .join('\n')}
-----END EC PRIVATE KEY-----`

  const key = await importECPrivateKey(strippedPem, alg, { extractable: true })
  assert.equal((key.algorithm as EcKeyAlgorithm).namedCurve, crv)
  assert.equal((await exportJWK(key)).d, d)
})

test('legacy imports reject symmetric algorithms', async () => {
  const expected = {
    code: 'ERR_JOSE_NOT_SUPPORTED',
    message: 'Invalid or unsupported "alg" (Algorithm) value',
  }
  await assert.rejects(importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'HS256'), errorLike(expected))
  await assert.rejects(importRSAPublicKey(RSA_PKCS1_PUBLIC_PEM, 'A128KW'), errorLike(expected))
  await assert.rejects(importECPrivateKey(EC_VECTORS[0]!.pem, 'HS256'), errorLike(expected))
})

test('legacy imports validate the PEM label and input type', async () => {
  await assert.rejects(
    importRSAPrivateKey('not a pem' as never, 'RS256'),
    new TypeError('"pkcs1" must be PKCS#1 formatted string'),
  )
  await assert.rejects(
    importRSAPrivateKey(RSA_PKCS1_PUBLIC_PEM, 'RS256'),
    new TypeError('"pkcs1" must be PKCS#1 formatted string'),
  )
  await assert.rejects(
    importRSAPublicKey(42 as never, 'RS256'),
    new TypeError('"pkcs1" must be PKCS#1 formatted string'),
  )
  await assert.rejects(
    importECPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'ES256'),
    new TypeError('"sec1" must be SEC1 formatted string'),
  )
})

test('legacy imports honor and snapshot the extractable option', async () => {
  assert.equal((await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RS256')).extractable, false)
  assert.equal(
    (await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RS256', { extractable: true })).extractable,
    true,
  )
  assert.equal((await importECPrivateKey(EC_VECTORS[0]!.pem, 'ES256')).extractable, false)
  assert.equal(
    (await importECPrivateKey(EC_VECTORS[0]!.pem, 'ES256', { extractable: true })).extractable,
    true,
  )

  let reads = 0
  const key = await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RS256', {
    get extractable() {
      return reads++ === 0 ? false : true
    },
  })
  assert.equal(reads, 1)
  assert.equal(key.extractable, false)

  await assert.rejects(
    importRSAPublicKey(RSA_PKCS1_PUBLIC_PEM, 'RS256', { extractable: 'false' as never }),
    TypeError,
  )
})

test('malformed SEC1 input fails as JOSENotSupported with the parse error as cause', async () => {
  const truncated = EC_VECTORS[0]!.pem
    .split('\n')
    .slice(0, 2)
    .join('\n')
    .concat('\n-----END EC PRIVATE KEY-----')
  await assert.rejects(importECPrivateKey(truncated, 'ES256'), (error: unknown) => {
    assert.ok(error instanceof errors.JOSENotSupported)
    assert.equal((error as Error).message, 'Invalid or unsupported key format')
    assert.ok((error as { cause: unknown }).cause instanceof Error)
    return true
  })
})

test('a SEC1 with neither parameters nor a public point cannot infer its curve', async () => {
  const { pem } = EC_VECTORS[0]!
  const der = decodeBase64(pem.replace(/(?:-----(?:BEGIN|END) EC PRIVATE KEY-----|\s)/g, ''))
  // Keep only version (INTEGER) and privateKey (OCTET STRING), drop both optional elements.
  const versionLen = der[3]!
  const version = der.subarray(2, 4 + versionLen)
  const keyLen = der[5 + versionLen]!
  const privateKey = der.subarray(4 + versionLen, 6 + versionLen + keyLen)
  const body = concat(version, privateKey)
  const minimal = concat(new Uint8Array([0x30, body.length]), body)
  const minimalPem = `-----BEGIN EC PRIVATE KEY-----
${encodeBase64(minimal)
  .match(/.{1,64}/g)!
  .join('\n')}
-----END EC PRIVATE KEY-----`
  await assert.rejects(
    importECPrivateKey(minimalPem, 'ES256'),
    new errors.JOSENotSupported('Invalid or unsupported key format'),
  )
})

test('malformed PKCS#1 input is rejected by the system key importer', async () => {
  // The PKCS#1 wrapper only prepends the AlgorithmIdentifier; the WebCrypto importer validates the
  // inner RSAPrivateKey/RSAPublicKey content and raises its native DataError, matching the existing
  // importSPKI/importPKCS8 behavior for structurally invalid DER. "Zm9vYmFy" is valid base64
  // ("foobar") but not a valid RSAPrivateKey/RSAPublicKey structure.
  const garbage = 'Zm9vYmFy'
  await assert.rejects(
    importRSAPrivateKey(
      `-----BEGIN RSA PRIVATE KEY-----\n${garbage}\n-----END RSA PRIVATE KEY-----`,
      'RS256',
    ),
    DOMException,
  )
  await assert.rejects(
    importRSAPublicKey(
      `-----BEGIN RSA PUBLIC KEY-----\n${garbage}\n-----END RSA PUBLIC KEY-----`,
      'RS256',
    ),
    DOMException,
  )
})

test('legacy private imports default to non-extractable like importPKCS8', async () => {
  const pkcs8 = await importPKCS8(
    // round-trip the RFC vector through a PKCS#8 wrapper for a like-for-like default comparison
    await (async () => {
      const legacy = await importRSAPrivateKey(RSA_PKCS1_PRIVATE_PEM, 'RS256', {
        extractable: true,
      })
      const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', legacy))
      return `-----BEGIN PRIVATE KEY-----
${encodeBase64(der)
  .match(/.{1,64}/g)!
  .join('\n')}
-----END PRIVATE KEY-----`
    })(),
    'RS256',
  )
  assert.equal(pkcs8.extractable, false)
})
