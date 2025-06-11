// Types for server responses (simplified, ensure they match your backend)
export interface ServerRegistrationOptions {
  challenge: string; // base64url
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string }; // user.id is base64url
  pubKeyCredParams: PublicKeyCredentialParameters[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  excludeCredentials?: { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }[]; // id is base64url, transports match AuthenticatorTransport
}

export interface ServerAuthenticationOptions {
  challenge: string; // base64url
  rpId?: string;
  allowCredentials?: { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }[]; // id is base64url
  userVerification?: UserVerificationRequirement;
  timeout?: number;
}

// Copied from server/src/types.ts for frontend use
export enum ActionType {
  CreateAccount = "CreateAccount",
  DeployContract = "DeployContract",
  FunctionCall = "FunctionCall",
  Transfer = "Transfer",
  Stake = "Stake",
  AddKey = "AddKey",
  DeleteKey = "DeleteKey",
  DeleteAccount = "DeleteAccount",
}

export interface SerializableActionArgs {
  action_type: ActionType;
  receiver_id?: string;
  method_name?: string;
  args?: string; // Base64 encoded string of JSON args
  deposit?: string; // yoctoNEAR as string
  gas?: string; // Gas as string
  amount?: string; // yoctoNEAR as string, for Transfer
  public_key?: string; // For AddKey, DeleteKey, Stake
  allowance?: string; // yoctoNEAR as string, for AddKey (FunctionCallAccessKey)
  method_names?: string[]; // For AddKey (FunctionCallAccessKey)
  code?: string; // Base64 encoded string of contract code, for DeployContract
  stake?: string; // yoctoNEAR as string, for Stake
  beneficiary_id?: string; // For DeleteAccount
}
