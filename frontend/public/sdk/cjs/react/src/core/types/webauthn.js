'use strict';

var encoders = require('../../utils/encoders.js');

// =================================================================
// 4. CONTRACT CALL TYPES
// =================================================================
/** VRF challenge data structure used in contract verification */
// export interface VrfChallengeData {
// }
class VRFChallenge {
    constructor(vrfChallengeData) {
        this.vrfInput = vrfChallengeData.vrfInput;
        this.vrfOutput = vrfChallengeData.vrfOutput;
        this.vrfProof = vrfChallengeData.vrfProof;
        this.vrfPublicKey = vrfChallengeData.vrfPublicKey;
        this.userId = vrfChallengeData.userId;
        this.rpId = vrfChallengeData.rpId;
        this.blockHeight = vrfChallengeData.blockHeight;
        this.blockHash = vrfChallengeData.blockHash;
    }
    /**
     * Decode VRF output and use first 32 bytes as WebAuthn challenge
     * @returns 32-byte Uint8Array
     */
    outputAs32Bytes() {
        let vrfOutputBytes = encoders.base64UrlDecode(this.vrfOutput);
        return vrfOutputBytes.slice(0, 32);
    }
}

exports.VRFChallenge = VRFChallenge;
//# sourceMappingURL=webauthn.js.map
