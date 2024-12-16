import { JwkDidSupportedKeyTypes, KeyUse, SupportedKeyTypes } from './types/utility-types.js'
import type { VerificationMethod, JsonWebKey, DIDResolutionResult } from 'did-resolver'
import { secp256k1 } from '@noble/curves/secp256k1'
import { p256 } from '@noble/curves/p256'
import { bytesToBase64url, hexToBytes } from 'did-jwt'
import { extractPublicKeyHex } from './did-utils.js'
import { extractIssuer } from './credential-utils.js'

export function getKeyUse(keyType: JwkDidSupportedKeyTypes, passedKeyUse?: KeyUse): KeyUse {
  if (passedKeyUse) {
    if (passedKeyUse !== 'sig' && passedKeyUse !== 'enc') {
      throw new Error('illegal_argument: Key use must be sig or enc')
    }
    if (passedKeyUse === 'sig' && keyType === 'X25519') {
      throw new Error('illegal_argument: X25519 keys cannot be used for signing')
    }
    if (passedKeyUse === 'enc' && keyType === 'Ed25519') {
      throw new Error('illegal_argument: Ed25519 keys cannot be used for encryption')
    }
    return passedKeyUse
  }
  switch (keyType) {
    case 'Secp256k1':
    case 'Secp256r1':
    case 'Ed25519':
      return 'sig'
    case 'X25519':
      return 'enc'
    default:
      throw new Error('illegal_argument: Unknown key type')
  }
}

export function isJWK(data: unknown): data is JsonWebKey {
  if (
    typeof data === 'object' &&
    data &&
    'crv' in data &&
    typeof data.crv === 'string' &&
    'kty' in data &&
    'x' in data &&
    typeof data.x === 'string' &&
    ((data.kty === 'EC' && 'y' in data && typeof data.y === 'string') ||
      (data.kty === 'OKP' && !('y' in data)))
  ) {
    return true
  }
  return false
}

export function createJWK(
  keyType: JwkDidSupportedKeyTypes,
  pubKey: string | Uint8Array,
  passedKeyUse?: KeyUse,
): JsonWebKey | undefined {
  try {
    const keyUse = getKeyUse(keyType, passedKeyUse)
    switch (keyType) {
      case SupportedKeyTypes.Secp256k1: {
        const point = secp256k1.ProjectivePoint.fromHex(pubKey).toAffine()

        return {
          alg: 'ES256K',
          crv: 'secp256k1',
          kty: 'EC',
          ...(keyUse && { use: keyUse }),
          // FIXME: test endianness of the toString(16) output
          x: bytesToBase64url(hexToBytes(point.x.toString(16))),
          y: bytesToBase64url(hexToBytes(point.y.toString(16))),
        } as JsonWebKey
      }
      case SupportedKeyTypes.Secp256r1: {
        const point = p256.ProjectivePoint.fromHex(pubKey).toAffine()

        return {
          alg: 'ES256',
          crv: 'P-256',
          kty: 'EC',
          ...(keyUse && { use: keyUse }),
          x: bytesToBase64url(hexToBytes(point.x.toString(16))),
          y: bytesToBase64url(hexToBytes(point.y.toString(16))),
        } as JsonWebKey
      }
      case SupportedKeyTypes.Ed25519:
        return {
          alg: 'EdDSA',
          crv: 'Ed25519',
          kty: 'OKP',
          ...(keyUse && { use: keyUse }),
          x: bytesToBase64url(typeof pubKey === 'string' ? hexToBytes(pubKey) : pubKey),
        } as JsonWebKey
      case SupportedKeyTypes.X25519:
        return {
          alg: 'ECDH-ES',
          crv: 'X25519',
          kty: 'OKP',
          ...(keyUse && { use: keyUse }),
          x: bytesToBase64url(typeof pubKey === 'string' ? hexToBytes(pubKey) : pubKey),
        } as JsonWebKey
      default:
        throw new Error(`not_supported: Failed to create JWK using ${keyType}`)
    }
  } catch (error) {
    throw error
  }
}

export function generateJwkFromVerificationMethod(
  keyType: JwkDidSupportedKeyTypes,
  key: VerificationMethod,
  keyUse?: KeyUse,
) {
  const { publicKeyHex, keyType: extractedType } = extractPublicKeyHex(key)
  return createJWK(keyType, publicKeyHex, keyUse)
}

const isString = (value: any): value is string => typeof value === 'string'

/**
 * Validate the JOSE header of a JWT
 * Only support kid with DID URL
 * @param header
 * @param payload
 * Ref: https://www.w3.org/TR/vc-jose-cose/#using-header-params-claims-key-discovery
 * Ref: https://www.w3.org/TR/vc-jose-cose/#jose-header-parameters-jwt-claims
 */
export const validateHeaderJOSE = (header: any, payload: any) => {
  // Check for 'alg' (Algorithm - Required)
  if (!isString(header.alg)) {
    throw new Error('alg must be present and a string')
  }

  // Reject "none" algorithm as per spec
  if (header.alg === 'none') {
    throw new Error('alg must not be "none"')
  }

  // Check for 'kid' (Key ID - Required)
  // https://www.w3.org/TR/vc-jose-cose/#kid
  if (!isString(header.kid)) {
    throw new Error('kid must be a string')
  }
  const isDidUrlKey = /^did:\w+:/.test(header.kid)
  if (!isDidUrlKey && header.kid.startsWith('did:')) {
    throw new Error('kid must be a full DID URL when starting with "did:"')
  }

  // Check for 'iss' (Issuer - Optional)
  // https://www.w3.org/TR/vc-jose-cose/#iss
  if ('iss' in header) {
    if (!isString(header.iss)) {
      throw new Error('iss must be a string when present')
    }

    if (!('issuer' in payload)) {
      throw new Error('issuer must be present in payload when iss is in header')
    }

    let issuerId = extractIssuer(payload, { removeParameters: true })
    // Check if 'iss' matches 'issuer.id' or 'issuer' string
    if (issuerId && header['iss'] !== issuerId) {
      throw new Error('iss in header does not match issuer value')
    }
  }

  // Check for 'cty' (Content Type - Optional)
  // https://www.w3.org/TR/vc-jose-cose/#securing-with-jose
  if ('cty' in header) {
    if (!isString(header.cty)) {
      throw new Error('cty must be a string')
    }
  }

  // Check for 'typ' (Type - Optional)
  // https://www.w3.org/TR/vc-jose-cose/#securing-with-jose
  if ('typ' in header) {
    if (!isString(header.typ)) {
      throw new Error('typ must be a string')
    }
  }
}

export const resolveDidAndGetVerificationMethods = async (
  didUrl: string,
  context: { agent: { resolveDid: (params: { didUrl: string }) => Promise<DIDResolutionResult> } },
): Promise<VerificationMethod[]> => {
  const doc = await context.agent.resolveDid({ didUrl })
  if (!doc || !doc.didDocument?.verificationMethod) {
    throw new Error('Could not resolve DID or find verification methods')
  }
  return doc.didDocument.verificationMethod
}

export const findMatchingVerificationMethod = async (
  methods: VerificationMethod[],
  types: string[] = ['JsonWebKey'],
  kid?: string,
): Promise<VerificationMethod> => {
  let matchingMethod: VerificationMethod | undefined

  if (kid) {
    // If a kid is provided, find by kid first
    matchingMethod = methods.find((method) => method.id === kid)
    if (!matchingMethod) {
      throw new Error("kid does not match any key in the issuer's DID document")
    }
  } else {
    // If no kid, find by type
    matchingMethod = methods.find((method) => types.includes(method.type))
  }

  if (!matchingMethod) {
    throw new Error('No matching verification method found')
  }

  if (!types.includes(matchingMethod.type)) {
    throw new Error(`DID document: Key with kid "${kid}" is not of type: ${types.join(', ')}`)
  }

  if (!matchingMethod.publicKeyJwk) {
    throw new Error('The matching verification method does not contain a publicKeyJwk')
  }

  return matchingMethod
}
