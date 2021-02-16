# Knot HTTP Requests Signer

Library used to sign http request as defined in https://tools.ietf.org/html/draft-cavage-http-signatures-12.
More info on why we use it can be found [here](https://doc.knotcity.io/services/http-signature/).

# Installation

This project is written in Typescript using Node.js 12 and targeting es2017.
It MAY work for older versions of Node.js.

Install using npm:
```
npm install @knotcity/http-request-signer
```

# Usage

You have a client and server example in the `example/` folder.
Import the module the same way you do normally.

```
// Javascript
const hrs = require('@knotcity/http-request-signer');
// Typescript
import hrs = require('@knotcity/http-request-signer');
```

## Generating a key

You can use the [crypto module](https://nodejs.org/api/crypto.html#crypto_crypto_generatekeypair_type_options_callback) from Node.js to generate a key pair or the utility function in the package to generate an ec `secp521r1` curve.

```
const keyPair = hrs.generateECKeyPair();
// Public key
keyPair.publicKey;
// Private key
keyPair.privateKey;
```

## Signing a request

To sign a request you need to add the `Authorization` header with the value given by the `generateAuthorization` function.

```
import http = require('http');

// Make a request using node's http module, but you can also use other modules like axios
const req = http.request(...);

// Fetch the private key from somewhere safe
const privKey = "...";

// Generate the signature
const auth = hrs.generateAuthorization({
    headers: req.getHeaders(),
    method: req.method,
    path: req.path
}, {
    headers: ['date', '(request-target)', 'content-length'], // List of header to use in the signature
    privateKey: privKey, // Private key
    hash: 'sha256', // Hash to use
    algorithm: 'ecdsa', // Algorithm used for the key
    keyId: 'keyn1' // The key identifier (this is defined by you, to allow to find the public key matching the private key)
});

// Add signature to request
req.setHeader('authorization', auth);
```

## Verifying a signature

The verification process is similar to the signature process as we collect the same info, but using the public key instead of the private key. (as the server does not know the private key).

```
try
{
    // Extract all components of the Authorization header
    const components = hrs.parseAuthorizationHeader(req.headers.authorization);
    
    // Here you would get the keyId from the components and fetch the matching public key
    const pubKey = "...";

    const valid = verifyAuthorization(components, {
            headers: req.headers,
            method: req.method || '',
            path: req.url || ''
        }, pubKey);
}
catch(err)
{
    // Throws if the header cannot be parsed
}
```
