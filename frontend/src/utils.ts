
export const bufferEncode = (value: ArrayBuffer): string => {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export const bufferDecode = (value: string): ArrayBuffer => {
  value = value.replace(/-/g, "+").replace(/_/g, "/");
  while (value.length % 4) {
    value += "=";
  }
  const base64 = atob(value);
  const buffer = new Uint8Array(base64.length);
  for (let i = 0; i < base64.length; i++) {
    buffer[i] = base64.charCodeAt(i);
  }
  return buffer.buffer;
}

// Helper to convert PublicKeyCredential to JSON for the server
// Matches RegistrationResponseJSON / AuthenticationResponseJSON structure from @simplewebauthn/server
export const publicKeyCredentialToJSON = (pubKeyCred: PublicKeyCredential): any => {
  if (pubKeyCred.response instanceof AuthenticatorAttestationResponse) {
    const attestationResponse = pubKeyCred.response;
    return {
      id: pubKeyCred.id,
      rawId: bufferEncode(pubKeyCred.rawId),
      type: pubKeyCred.type,
      clientExtensionResults: pubKeyCred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufferEncode(attestationResponse.clientDataJSON),
        attestationObject: bufferEncode(attestationResponse.attestationObject),
        transports: (attestationResponse as any).getTransports ? (attestationResponse as any).getTransports() : undefined,
      },
    };
  } else if (pubKeyCred.response instanceof AuthenticatorAssertionResponse) {
    const assertionResponse = pubKeyCred.response;
    return {
      id: pubKeyCred.id,
      rawId: bufferEncode(pubKeyCred.rawId),
      type: pubKeyCred.type,
      clientExtensionResults: pubKeyCred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufferEncode(assertionResponse.clientDataJSON),
        authenticatorData: bufferEncode(assertionResponse.authenticatorData),
        signature: bufferEncode(assertionResponse.signature),
        userHandle: assertionResponse.userHandle ? bufferEncode(assertionResponse.userHandle) : undefined,
      },
    };
  }
  throw new Error('Unsupported PublicKeyCredential response type');
}