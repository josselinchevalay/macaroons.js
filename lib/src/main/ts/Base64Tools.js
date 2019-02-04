"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Base64Tools {
    static transformBase64UrlSafe2Base64(base64) {
        return base64.replace(/-/g, '+').replace(/_/g, '/') + Base64Tools.BASE64_PADDING.substr(0, 3 - (base64.length % 3));
    }
    static encodeBase64UrlSafe(base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
}
Base64Tools.BASE64_PADDING = '===';
exports.default = Base64Tools;
//# sourceMappingURL=Base64Tools.js.map