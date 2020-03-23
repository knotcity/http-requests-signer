import crypto = require('crypto');

export function sign(data: string, privateKey: string, hash: Hash)
{
    return crypto.createSign(hash).update(data).sign(privateKey, 'base64');
}

export function buildAuthorizationHeader({ keyId, algorithm, hash, headers, signature }: AuthorizationHeaderComponents)
{
    return `Signature keyId="${keyId}",algorithm="${algorithm}-${hash}",headers="${headers.map(h => h.toLowerCase()).join(' ')}",signature="${signature}"`;
}
