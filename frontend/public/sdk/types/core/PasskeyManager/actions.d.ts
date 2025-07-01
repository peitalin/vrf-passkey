import type { ActionArgs } from '../types/actions';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
/**
 * Core action execution function without React dependencies
 * Handles blockchain transactions with PRF-based signing
 */
export declare function executeAction(context: PasskeyManagerContext, nearAccountId: string, actionArgs: ActionArgs, options?: ActionOptions): Promise<ActionResult>;
//# sourceMappingURL=actions.d.ts.map