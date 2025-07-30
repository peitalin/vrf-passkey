import { base64UrlEncode } from "../../utils";
import {
  type WebAuthnAuthenticationCredential,
  type WebAuthnRegistrationCredential,
} from '../types/webauthn';

/**
 * Dual PRF outputs for separate encryption and signing key derivation
 */
export interface DualPrfOutputs {
  /** Base64-encoded PRF output from prf.results.first for AES-GCM encryption */
  chacha20PrfOutput: string;
  /** Base64-encoded PRF output from prf.results.second for Ed25519 signing */
  ed25519PrfOutput: string;
}

/**
 * Extract the first PRF output from WebAuthn credential
 * For ChaCha20 derivation.
 *
 * @param credential - WebAuthn credential with dual PRF extension results
 * @returns Base64url-encoded ChaCha20 PRF output
 * @throws Error if ChaCha20 PRF output is not available
 */
export function extractChaCha20PrfOutput(credential: PublicKeyCredential): { chacha20PrfOutput: string } {
  const extensions = credential.getClientExtensionResults();
  const chacha20PrfOutput = extensions.prf?.results?.first as ArrayBuffer;
  if (!chacha20PrfOutput) {
    throw new Error('PRF output required but not available - ensure first PRF output is present');
  }
  return {
    chacha20PrfOutput: base64UrlEncode(chacha20PrfOutput),
  };
}

/**
 * Extract dual PRF outputs from WebAuthn credential
 *
 * @param credential - WebAuthn credential with dual PRF extension results
 * @returns DualPrfOutputs with both AES and Ed25519 PRF outputs
 * @throws Error if dual PRF outputs are not available
 */
export function extractDualPrfOutputs(credential: PublicKeyCredential): DualPrfOutputs {
  const extensions = credential.getClientExtensionResults();
  const chacha20PrfOutput = extensions.prf?.results?.first;
  const ed25519PrfOutput = extensions.prf?.results?.second;

  if (!chacha20PrfOutput || !ed25519PrfOutput) {
    throw new Error('Dual PRF outputs required but not available - ensure both first and second PRF outputs are present');
  }

  return {
    chacha20PrfOutput: base64UrlEncode(chacha20PrfOutput as ArrayBuffer),
    ed25519PrfOutput: base64UrlEncode(ed25519PrfOutput as ArrayBuffer)
  };
}
/**
 * Extract dual PRF outputs from WebAuthn credential extension results
 * ENCODING: Uses base64url for WASM compatibility
 */
function extractDualPrfFromCredential(credential: PublicKeyCredential): {
  first?: string;
  second?: string;
} {
  const extensionResults = credential.getClientExtensionResults();
  const prfResults = extensionResults?.prf?.results;
  if (!prfResults) {
    throw new Error('Missing PRF results from credential, use a PRF-enabled Authenticator');
  }
  return {
    first: prfResults?.first ? base64UrlEncode(prfResults.first as ArrayBuffer) : undefined,
    second: prfResults?.second ? base64UrlEncode(prfResults.second as ArrayBuffer) : undefined
  };
}

type SerializableCredential = WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;

/**
 * Serialize PublicKeyCredential with PRF handling for both authentication and registration
 * - Handles dual PRF extraction consistently
 * - Uses base64url encoding for WASM compatibility
 */
export function serializeCredentialWithPRF<C extends SerializableCredential>(
  credential: PublicKeyCredential
): C {
  // Check if this is a registration credential by looking for attestationObject
  const response = credential.response;
  const isRegistration = 'attestationObject' in response;

  const credentialBase = {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {},
    clientExtensionResults: {
      prf: {
        results: extractDualPrfFromCredential(credential)
      }
    }
  }

  if (isRegistration) {
    const attestationResponse = response as AuthenticatorAttestationResponse;
    return {
      ...credentialBase,
    response: {
      clientDataJSON: base64UrlEncode(attestationResponse.clientDataJSON),
      attestationObject: base64UrlEncode(attestationResponse.attestationObject),
      transports: attestationResponse.getTransports() || [],
    },
    } as C;
  } else {
    const assertionResponse = response as AuthenticatorAssertionResponse;
    return {
      ...credentialBase,
      response: {
        clientDataJSON: base64UrlEncode(assertionResponse.clientDataJSON),
        authenticatorData: base64UrlEncode(assertionResponse.authenticatorData),
        signature: base64UrlEncode(assertionResponse.signature),
        userHandle: assertionResponse.userHandle ? base64UrlEncode(assertionResponse.userHandle as ArrayBuffer) : null,
      },
    } as C;
    }
  }

/**
 * Removes PRF outputs from the credential and returns the credential without PRF along with just the ChaCha20 PRF output
 * @param credential - The WebAuthn credential containing PRF outputs
 * @returns Object containing credential with PRF removed and the extracted ChaCha20 PRF output
 * Does not return the second PRF output (Ed25519 PRF)
 */
export function takeChaCha20PrfOutput(credential: SerializableCredential): ({
  credentialWithoutPrf: SerializableCredential,
  chacha20PrfOutput: string
}) {
  const chacha20PrfOutput = credential.clientExtensionResults?.prf?.results?.first;
  if (!chacha20PrfOutput) {
    throw new Error('PRF output missing from credential.clientExtensionResults: required for secure key decryption');
  }

  const credentialWithoutPrf: SerializableCredential = {
    ...credential,
    clientExtensionResults: {
      ...credential.clientExtensionResults,
      prf: {
        ...credential.clientExtensionResults?.prf,
        results: {
          first: null, // ChaCha20 PRF output
          second: null // Ed25519 PRF output
        }
      }
    }
  };

  return { credentialWithoutPrf, chacha20PrfOutput };
}
