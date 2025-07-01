/**
 * Utility method for base64url encoding
 */
/**
 * Utility function for base64url decoding
 */
function base64UrlDecode(base64Url) {
    const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
const bufferEncode = (value) => {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
};

export { base64UrlDecode, bufferEncode };
//# sourceMappingURL=encoders.js.map
