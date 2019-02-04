"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const CAVEAT_PREFIX = /time < .*/;
const CAVEAT_PREFIX_LEN = "time < ".length;
function TimestampCaveatVerifier(caveat) {
    if (CAVEAT_PREFIX.test(caveat)) {
        var parsedTimestamp = new Date(caveat.substr(CAVEAT_PREFIX_LEN).trim());
        var time = parsedTimestamp.getTime();
        return time > 0 && Date.now() < time;
    }
    return false;
}
exports.default = TimestampCaveatVerifier;
//# sourceMappingURL=TimestampCaveatVerifier.js.map