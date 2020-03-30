import http = require('http');

import { verifyAuthorization } from '../dist';
import { parseAuthorizationHeader } from '../dist/verifier';

const pubKey = '-----BEGIN PUBLIC KEY-----\n' +
    'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBV3G4qtmU+GT+OihDP5sGZKNQMUzw\n' +
    '4NA0t2F4PDiLqXp2bCO1a2q1ui9gwROfixMlccBabaEgDPw3fWyJ9NSGEh0AQej8\n' +
    'bZ93EbNBp0mDz9k0Uc+tyPl9LIptqeDvAUgaOUZ6LZorXmDNV15aLXUTzNFs5jP2\n' +
    'PIFP5prEe0LCbfTkrHE=\n' +
    '-----END PUBLIC KEY-----\n';

const server = http.createServer((req, res) =>
{
    let data = '';
    req.on('data', chunk =>
    {
        data += chunk;
    });
    req.on('end', () =>
    {
        if (req.headers.authorization)
        {
            try
            {
                const components = parseAuthorizationHeader(req.headers.authorization);
                // Fetch pubkey from keyId
                if (verifyAuthorization(components, {
                    headers: req.headers,
                    method: req.method || '',
                    path: req.url || ''
                }, pubKey
                ))
                {
                    res.writeHead(200);
                    res.end('Valid signature!');
                }
                else
                {
                    res.writeHead(500);
                    res.end('Invalid signature');
                }
            }
            catch (err)
            {
                console.log(err);
                res.writeHead(500);
                res.end('Invalid authorization header');
            }
        }
        else
        {
            res.writeHead(500);
            res.end('Missing authorization header');
        }
    });
});
server.listen(8080);
