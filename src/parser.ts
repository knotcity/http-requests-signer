import { validateAlgorithm, AuthorizationHeaderComponentsNullable } from './utils.js';

export function parseAuthorizationHeader(auth: string)
{
    const firstSpace = auth.indexOf(' ');
    if (firstSpace == -1)
    {
        throw new Error('Given authorization header is not valid, could not find the space between "Signature" and the other parts of the header');
    }
    const firstWord = auth.substring(0, firstSpace);
    const remaining = auth.substring(firstSpace + 1);
    if (firstWord.toLowerCase() !== 'signature')
    {
        throw new Error('Given authorization header do not start with Signature');
    }
    const parts = remaining.split(/,(?!(?=[^"]*"[^"]*(?:"[^"]*"[^"]*)*$))/g);
    const output: Partial<AuthorizationHeaderComponentsNullable> = {};
    for (const p of parts)
    {
        const eqIdx = p.indexOf('=');
        if (eqIdx == -1)
        {
            throw new Error('Given authorization header is not valid, missing an equal sign in "' + p + '"');
        }
        const key = p.substring(0, eqIdx);
        let value = p.substring(eqIdx + 1);
        if (value.length < 2 || !value.startsWith('"') || !value.endsWith('"'))
        {
            throw new Error('Given authorization header is not valid, value should be quoted with double quotes in "' + p + '"');
        }
        value = value.substring(1, value.length - 1);
        switch (key)
        {
            case 'keyId':
                output.keyId = value;
                break;
            case 'algorithm':
                {
                    const [algorithm, hash] = validateAlgorithm(value);
                    output.algorithm = algorithm;
                    output.hash = hash;
                }
                break;
            case 'headers':
                output.headers = value.split(' ');
                break;
            case 'signature':
                output.signature = value;
                break;
            default:
                throw new Error('Given authorization header is not valid, invalid key found in "' + p + '"');
        }
    }
    return output as AuthorizationHeaderComponentsNullable;
}
