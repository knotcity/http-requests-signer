import http = require('http');

import { generateAuthorization } from '../dist';

const privKey = '-----BEGIN PRIVATE KEY-----\n' +
    'MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAxfrhuLtAvLjB7rLX\n' +
    'DvGT67B2ro4c9xy+SKJi0GQsH8k5fY7pmLqbjaeb/rbQeeEMHCUUDeHwkHcIN4EF\n' +
    '+qyIKM+hgYkDgYYABAFXcbiq2ZT4ZP46KEM/mwZko1AxTPDg0DS3YXg8OIupenZs\n' +
    'I7VrarW6L2DBE5+LEyVxwFptoSAM/Dd9bIn01IYSHQBB6Pxtn3cRs0GnSYPP2TRR\n' +
    'z63I+X0sim2p4O8BSBo5RnotmiteYM1XXlotdRPM0WzmM/Y8gU/mmsR7QsJt9OSs\n' +
    'cQ==\n' +
    '-----END PRIVATE KEY-----\n';

const content = 'Hellooo\n How are you ?';

const req = http.request('http://localhost:8080?id=50', {
    method: 'POST',
    headers: {
        'content-length': content.length,
        'date': +new Date()
    }
}, (resp) =>
{
    let data = '';

    // A chunk of data has been recieved.
    resp.on('data', (chunk) =>
    {
        data += chunk;
    });

    // The whole response has been received. Print out the result.
    resp.on('end', () =>
    {
        console.log(data);
    });
});

const auth = generateAuthorization({
    headers: req.getHeaders(),
    method: req.method,
    path: req.path
}, {
    headers: ['date', '(request-target)', 'content-length'],
    privateKey: privKey,
    hash: 'sha256',
    algorithm: 'ecdsa',
    keyId: 'keyn1'
});

req.setHeader('authorization', auth);

req.write(content);
req.end();
