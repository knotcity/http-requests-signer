import crypto = require('crypto');

import { verify } from './verifier';
import { sign, buildAuthorizationHeader } from './signer';
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

export function generateAuthorization(data: DenormalizedData, { headers, keyId, privateKey, hash, algorithm }: { headers: string[], keyId: string, privateKey: string, hash: Hash, algorithm: Algo })
{
    const normalized = normalizeData(data, { headers });
    const stringData = stringifyNormalizedData(normalized);
    const signature = sign(stringData, privateKey, hash);
    return buildAuthorizationHeader({
        keyId,
        signature,
        algorithm,
        hash,
        headers
    });
}

export function verifyAuthorization(components: AuthorizationHeaderComponents, data: DenormalizedData, pubKey: string)
{
    const normalized = normalizeData(data, { headers: components.headers });
    const stringData = stringifyNormalizedData(normalized);
    return verify(stringData, components.signature, pubKey, components.hash);
}

export { parseAuthorizationHeader } from './verifier';