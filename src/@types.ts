type Algo = 'rsa' | 'dsa' | 'ecdsa';
type Hash = 'sha256' | 'sha512';

type OrderedHeaderList = Array<{
    name: string,
    values: string[]
}>;

interface DenormalizedData
{
    headers: { [header: string]: number | string | string[] | undefined };
    content: any;
    method: string;
    path: string;
}

interface NormalizedData
{
    headers: OrderedHeaderList;
    content: string;
}

interface AuthorizationHeaderComponents
{
    keyId: string;
    algorithm: Algo;
    hash: Hash;
    headers: string[];
    signature: string
}
