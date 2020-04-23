import crypto = require('crypto');

import type { Hash } from './utils';

export function verify(data: string, signature: string, publicKey: string, hash: Hash)
{
    return crypto.createVerify(hash).update(data).verify(publicKey, signature, 'base64');
}


