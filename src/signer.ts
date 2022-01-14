import * as crypto from 'crypto';

import type { Hash } from './utils';

export function sign(data: string, privateKey: string, hash: Hash)
{
    return crypto.createSign(hash).update(data).sign(privateKey, 'base64');
}
