"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class MacaroonsConstants {
}
MacaroonsConstants.MACAROON_MAX_STRLEN = 32768;
MacaroonsConstants.MACAROON_MAX_CAVEATS = 65536;
MacaroonsConstants.MACAROON_SUGGESTED_SECRET_LENGTH = 32;
MacaroonsConstants.MACAROON_HASH_BYTES = 32;
MacaroonsConstants.PACKET_PREFIX_LENGTH = 4;
MacaroonsConstants.PACKET_MAX_SIZE = 65535;
MacaroonsConstants.MACAROON_SECRET_KEY_BYTES = 32;
MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES = 24;
MacaroonsConstants.MACAROON_SECRET_TEXT_ZERO_BYTES = 32;
MacaroonsConstants.MACAROON_SECRET_BOX_ZERO_BYTES = 16;
MacaroonsConstants.SECRET_BOX_OVERHEAD = MacaroonsConstants.MACAROON_SECRET_TEXT_ZERO_BYTES - MacaroonsConstants.MACAROON_SECRET_BOX_ZERO_BYTES;
MacaroonsConstants.VID_NONCE_KEY_SZ = MacaroonsConstants.MACAROON_SECRET_NONCE_BYTES + MacaroonsConstants.MACAROON_HASH_BYTES + MacaroonsConstants.SECRET_BOX_OVERHEAD;
MacaroonsConstants.LOCATION = "location";
MacaroonsConstants.LOCATION_BYTES = new Buffer(MacaroonsConstants.LOCATION, 'ascii');
MacaroonsConstants.IDENTIFIER = "identifier";
MacaroonsConstants.IDENTIFIER_BYTES = new Buffer(MacaroonsConstants.IDENTIFIER, 'ascii');
MacaroonsConstants.SIGNATURE = "signature";
MacaroonsConstants.SIGNATURE_BYTES = new Buffer(MacaroonsConstants.SIGNATURE, 'ascii');
MacaroonsConstants.CID = "cid";
MacaroonsConstants.CID_BYTES = new Buffer(MacaroonsConstants.CID, 'ascii');
MacaroonsConstants.VID = "vid";
MacaroonsConstants.VID_BYTES = new Buffer(MacaroonsConstants.VID, 'ascii');
MacaroonsConstants.CL = "cl";
MacaroonsConstants.CL_BYTES = new Buffer(MacaroonsConstants.CL, 'ascii');
MacaroonsConstants.LINE_SEPARATOR_STR = '\n';
MacaroonsConstants.LINE_SEPARATOR = MacaroonsConstants.LINE_SEPARATOR_STR.charCodeAt(0);
MacaroonsConstants.LINE_SEPARATOR_LEN = 1;
MacaroonsConstants.KEY_VALUE_SEPARATOR_STR = ' ';
MacaroonsConstants.KEY_VALUE_SEPARATOR = MacaroonsConstants.KEY_VALUE_SEPARATOR_STR.charCodeAt(0);
MacaroonsConstants.KEY_VALUE_SEPARATOR_LEN = 1;
MacaroonsConstants.IDENTIFIER_CHARSET = "utf8";
exports.default = MacaroonsConstants;
//# sourceMappingURL=MacaroonsConstants.js.map