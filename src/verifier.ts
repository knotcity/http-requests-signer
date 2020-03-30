import crypto = require('crypto');

import { validateAlgorithm, Hash, AuthorizationHeaderComponents } from './utils';

export function verify(data: string, signature: string, publicKey: string, hash: Hash)
{
    return crypto.createVerify(hash).update(data).verify(publicKey, signature, 'base64');
}

export function parseAuthorizationHeader(auth: string)
{
    const fspace = auth.indexOf(' ');
    if (fspace == -1)
    {
        throw new Error("Given authorization header is not valid, could not find the space between 'Signature' and the other parts of the header");
    }
    const fword = auth.substr(0, fspace);
    const remaining = auth.substring(fspace + 1);
    if (fword.toLowerCase() !== "signature")
    {
        throw new Error("Given authorization header do not start with Signature");
    }
    const parts = remaining.split(/,(?!(?=[^"]*"[^"]*(?:"[^"]*"[^"]*)*$))/g);
    const output: Partial<AuthorizationHeaderComponents> = {};
    for (const p of parts)
    {
        const eqIdx = p.indexOf('=');
        if (eqIdx == -1)
        {
            throw new Error("Given authorization header is not valid, missing an equal sign in '" + p + "'");
        }
        const key = p.substr(0, eqIdx);
        let value = p.substr(eqIdx + 1);
        if (value.length < 2 || !value.startsWith('"') || !value.endsWith('"'))
        {
            throw new Error("Given authorization header is not valid, value should be quoted with double quotes in '" + p + "'");
        }
        value = value.substring(1, value.length - 1);
        switch (key)
        {
            case 'keyId':
                output.keyId = value;
                break;
            case 'algorithm':
                {
                    const algs = validateAlgorithm(value);
                    output.algorithm = algs[0];
                    output.hash = algs[1];
                }
                break;
            case 'headers':
                output.headers = value.split(' ');
                break;
            case 'signature':
                output.signature = value;
                break;
            default:
                throw new Error("Given authorization header is not valid, invalid key found in '" + p + "'");
        }
    }
    return output as AuthorizationHeaderComponents;
}
