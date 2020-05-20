import crypto = require('crypto');

import { sign } from './signer';
import { verify } from './verifier';
import { normalizeData, stringifyNormalizedData, DenormalizedData, AuthorizationHeaderComponents, Hash, Algo } from './utils';

export function generateECKeyPair()
{
    const keyPair = crypto.generateKeyPairSync('ec', {
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
    return keyPair;
}

export function generateAuthorization(data: DenormalizedData, { headers, keyId, privateKey, hash, algorithm, hide_algorithm }: { headers: string[], keyId: string, privateKey: string, hash: Hash, algorithm: Algo, hide_algorithm?: boolean })
{
    const normalized = normalizeData(data, { headers });
    const stringData = stringifyNormalizedData(normalized);
    const signature = sign(stringData, privateKey, hash);
    return `Signature keyId="${keyId}",algorithm="${(hide_algorithm || true) ? 'hs2019' : `${algorithm}-${hash}`}",headers="${headers.map(h => h.toLowerCase()).join(' ')}",signature="${signature}"`;
}

export function verifyAuthorization(components: AuthorizationHeaderComponents, data: DenormalizedData, pubKey: string)
{
    const normalized = normalizeData(data, { headers: components.headers });
    const stringData = stringifyNormalizedData(normalized);
    return verify(stringData, components.signature, pubKey, components.hash);
}

export { parseAuthorizationHeader } from './parser';
