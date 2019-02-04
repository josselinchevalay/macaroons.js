"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class BufferTools {
    static equals(a, b) {
        if (!Buffer.isBuffer(a)) {
            return undefined;
        }
        if (!Buffer.isBuffer(b)) {
            return undefined;
        }
        if (typeof a['equals'] === 'function') {
            return a['equals'](b);
        }
        if (a.length !== b.length) {
            return false;
        }
        for (let i = 0; i < a.length;) {
            if (a[i] !== b[i]) {
                return false;
            }
        }
        return true;
    }
}
exports.default = BufferTools;
//# sourceMappingURL=BufferTools.js.map