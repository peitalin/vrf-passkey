import type { LoginOptions, LoginResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
/**
 * Core login function that handles passkey authentication without React dependencies
 */
export declare function loginPasskey(context: PasskeyManagerContext, nearAccountId: string, options?: LoginOptions): Promise<LoginResult>;
//# sourceMappingURL=login.d.ts.map