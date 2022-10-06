import * as crypto from 'crypto';

import { parseAuthorizationHeader as _parseAuthorizationHeader } from './parser.js';

import { sign } from './signer.js';
import { verify } from './verifier.js';
import { Algo, AuthorizationHeaderComponents, DeNormalizedData, Hash, normalizeData, stringifyNormalizedData } from './utils.js';

export function generateECKeyPair()
{
    return crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp521r1',
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}

export function generateAuthorization(data: DeNormalizedData, { headers, keyId, privateKey, hash, algorithm, hide_algorithm }: { headers: string[], keyId: string, privateKey: string, hash: Hash, algorithm: Algo, hide_algorithm?: boolean })
{
    const normalized = normalizeData(data, { headers });
    const stringData = stringifyNormalizedData(normalized);
    const signature = sign(stringData, privateKey, hash);
    return `Signature keyId="${keyId}",algorithm="${(hide_algorithm || true) ? 'hs2019' : `${algorithm}-${hash}`}",headers="${headers.map(h => h.toLowerCase()).join(' ')}",signature="${signature}"`;
}

export function verifyAuthorization(components: AuthorizationHeaderComponents, data: DeNormalizedData, pubKey: string)
{
    const normalized = normalizeData(data, { headers: components.headers });
    const stringData = stringifyNormalizedData(normalized);
    return verify(stringData, components.signature, pubKey, components.hash);
}

export function parseAuthorizationHeader(auth: string) { // FIXME: To bypass the export through a getter
    return _parseAuthorizationHeader(auth);
}

export type { AuthorizationHeaderComponents, Algo, Hash } from './utils.js';

export default {
    generateECKeyPair,
    generateAuthorization,
    verifyAuthorization,
    parseAuthorizationHeader
};
