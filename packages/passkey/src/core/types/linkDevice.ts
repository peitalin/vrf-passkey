import {
  ActionResult,
  DeviceLinkingSSEEvent,
  EventCallback,
  OperationHooks
} from './passkeyManager';
import { VRFChallenge } from './webauthn';
import { AccountId } from './accountIds';

// === DEVICE LINKING TYPES ===
export interface DeviceLinkingQRData {
  accountId?: AccountId; // Optional - Device2 discovers this from contract polling
  device2PublicKey: string; // Device2 initiates and creates the QR code containing this public key
                            // for Device1 to scan and add it to their account.
  timestamp: number;
  version: string; // For future compatibility
}

export interface DeviceLinkingSession {
  accountId: AccountId | null; // Null until discovered from contract logs (Option F) or provided upfront (Option E)
  deviceNumber?: number; // Device number assigned by Device1 for device linking
  nearPublicKey: string;
  credential: PublicKeyCredential | null; // Null for Option F until real account discovered
  vrfChallenge: VRFChallenge | null; // Null for Option F until real account discovered
  status: DeviceLinkingStatus;
  createdAt: number;
  expiresAt: number;
  tempPrivateKey?: string; // For Option F flow - temporary private key before replacement
}

export type DeviceLinkingStatus =
  | 'generating'     // Device2: Generating credentials
  | 'waiting'        // Device2: Waiting for Device1 authorization
  | 'authorizing'    // Device1: Processing authorization
  | 'authorized'     // Device1: AddKey transaction sent
  | 'registering'    // Device2: Calling link_device_register_user
  | 'completed'      // Success
  | 'failed'         // Error state
  | 'expired';       // Timeout

export interface LinkDeviceResult extends ActionResult {
  device2PublicKey: string;
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

export interface StartDeviceLinkingOptionsDevice2 {
  cameraId?: string;
  onEvent?: EventCallback<DeviceLinkingSSEEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

export interface ScanAndLinkDeviceOptionsDevice1 {
  fundingAmount: string;
  cameraId?: string;
  cameraConfigs?: {
    facingMode?: 'user' | 'environment';
    width?: number;
    height?: number;
  };
  onEvent?: EventCallback<DeviceLinkingSSEEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}