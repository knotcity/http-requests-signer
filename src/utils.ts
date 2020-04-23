export type Algo = 'rsa' | 'dsa' | 'ecdsa';
export type Hash = 'sha256' | 'sha512';

export type OrderedHeaderList = Array<{
    name: string,
    values: string[]
}>;

export interface DenormalizedData
{
    headers: { [header: string]: number | string | string[] | undefined };
    method: string;
    path: string;
}

export interface NormalizedData
{
    headers: OrderedHeaderList;
}

export interface AuthorizationHeaderComponents
{
    keyId: string;
    algorithm: Algo;
    hash: Hash;
    headers: string[];
    signature: string
}

export const PK_ALG = ['rsa', 'dsa', 'ecdsa'];
export const HASH_ALG = ['sha256', 'sha512'];

export function validateAlgorithm(algorithm: string)
{
    var alg = algorithm.toLowerCase().split('-');

    if (alg.length !== 2)
    {
        throw new Error(algorithm + ' is not a valid algorithm');
    }

    if (!PK_ALG.includes(alg[0]))
    {
        throw new Error(alg[0] + ' keys are not supported');
    }

    if (!HASH_ALG.includes(alg[1]))
    {
        throw new Error(alg[1] + ' hash are not supported');
    }

    return alg as [Algo, Hash];
}

export function stringifyNormalizedData(data: NormalizedData)
{
    const components = new Array<string>();
    for (const h of data.headers)
    {
        const val = h.values.map(v => v.split(/\r?\n|\r/g).map(v => v.trim()).join(' ')).map(v => v.length == 0 ? ' ' : v).join(', ');
        components.push(h.name + ": " + val);
    }
    return components.join('\n');
}

export function normalizeData(data: DenormalizedData, config: { headers: string[] })
{
    if(config.headers.length == 0)
    {
        throw new Error('At least one header must be signed');
    }
    const headers: OrderedHeaderList = new Array();
    for (const h of config.headers)
    {
        const hl = h.toLowerCase();
        if (hl === '(request-target)')
        {
            headers.push({ name: '(request-target)', values: [data.method.toLowerCase() + " " + data.path] });
        }
        else
        {
            const hv = Object.entries(data.headers).find(v => v[0].toLowerCase() === hl);
            if (!hv || hv[1] === undefined)
            {
                throw new Error("Missing header " + h + " in request");
            }
            if (headers.find(e => e.name == hl))
            {
                throw new Error("Tried to add the same header multiple times: " + h);
            }
            headers.push({ name: hl, values: Array.isArray(hv[1]) ? hv[1].map(v => v.toString()) : [hv[1]?.toString()] });
        }
    }
   
    return {
        headers
    } as NormalizedData;
}
