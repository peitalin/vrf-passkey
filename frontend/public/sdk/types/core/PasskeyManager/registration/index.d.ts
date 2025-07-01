import type { RegistrationOptions, RegistrationResult } from '../../types/passkeyManager';
import type { PasskeyManagerContext } from '../index';
/**
 * Core registration function that handles passkey registration
 */
export declare function registerPasskey(context: PasskeyManagerContext, nearAccountId: string, options: RegistrationOptions): Promise<RegistrationResult>;
//# sourceMappingURL=index.d.ts.map