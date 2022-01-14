import * as crypto from 'crypto';

import type { Hash } from './utils.js';

export function sign(data: string, privateKey: string, hash: Hash)
{
    return crypto.createSign(hash).update(data).sign(privateKey, 'base64');
}
