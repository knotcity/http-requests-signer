import * as crypto from 'crypto';

import type { Hash } from './utils.js';

export function verify(data: string, signature: string, publicKey: string, hash: Hash)
{
    return crypto.createVerify(hash).update(data).verify(publicKey, signature, 'base64');
}
