import { ActionResult } from './passkeyManager';
import { VRFChallenge } from './webauthn';

// === DEVICE LINKING TYPES ===
export interface DeviceLinkingQRData {
  accountId?: string; // Optional - Device2 discovers this from contract polling
  devicePublicKey: string;
  timestamp: number;
  version: string; // For future compatibility
}

export interface DeviceLinkingSession {
  accountId: string | null; // Null until discovered from contract logs
  nearPublicKey: string;
  credential: PublicKeyCredential;
  vrfChallenge: VRFChallenge;
  status: DeviceLinkingStatus;
  createdAt: number;
  expiresAt: number;
}

export type DeviceLinkingStatus =
  | 'generating'     // Device2: Generating credentials
  | 'waiting'        // Device2: Waiting for Device1 authorization
  | 'authorizing'    // Device1: Processing authorization
  | 'authorized'     // Device1: AddKey transaction sent
  | 'registering'    // Device2: Calling verify_and_register_user
  | 'completed'      // Success
  | 'failed'         // Error state
  | 'expired';       // Timeout

export interface LinkDeviceResult extends ActionResult {
  devicePublicKey: string;
  transactionId?: string;
  fundingAmount: string;
  linkedToAccount?: string; // The account ID that the device key was added to
}

export class DeviceLinkingError extends Error {
  constructor(
    message: string,
    public code: DeviceLinkingErrorCode,
    public phase: 'generation' | 'authorization' | 'registration'
  ) {
    super(message);
  }
}

export enum DeviceLinkingErrorCode {
  INVALID_QR_DATA = 'INVALID_QR_DATA',
  ACCOUNT_NOT_OWNED = 'ACCOUNT_NOT_OWNED',
  AUTHORIZATION_TIMEOUT = 'AUTHORIZATION_TIMEOUT',
  INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
  REGISTRATION_FAILED = 'REGISTRATION_FAILED',
  SESSION_EXPIRED = 'SESSION_EXPIRED'
}