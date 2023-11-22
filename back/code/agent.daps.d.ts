export {KeyObject} from "crypto";

/** @see https://github.com/International-Data-Spaces-Association/IDS-G/blob/main/Components/IdentityProvider/DAPS/README.md#request-token-that-is-handed-in-at-daps-side Request token that is handed in at DAPS side */
export type DatRequestPayload = {
    "@context": "https://w3id.org/idsa/contexts/context.jsonld",
    "@type": "DatRequestPayload",
    iss: string,
    sub: string,
    aud: string,
    exp: number,
    nbf: number,
    iat: number
};

export type DatRequestToken = string;

export type DatRequestParam = {
    grant_type: string,
    client_assertion_type: string,
    client_assertion: DatRequestToken,
    scope: string
};

/** @see https://github.com/International-Data-Spaces-Association/IDS-G/blob/main/Components/IdentityProvider/DAPS/README.md#request-call-to-get-a-token Request call to get a token */
export type DatRequestQuery = string;

export type DatHeader = {
    alg: string,
    typ: string,
    kid: string
};

/** @see @see https://github.com/International-Data-Spaces-Association/IDS-G/blob/main/Components/IdentityProvider/DAPS/README.md#dynamic-attribute-token-content Dynamic Attribute Token Content */
export type DatPayload = {
    "@context": "https://w3id.org/idsa/contexts/context.jsonld",
    "@type": "DatPayload",
    iss: string,
    sub: string,
    aud: string,
    exp: number,
    nbf: number,
    iat: number,
    scope: Array<string>,
    securityProfile: string,
    referringConnector?: string,
    transportCertsSha256?: string | Array<string>,
    extendedGuarantee?: string
};

export type DynamicAttributeToken = string;

export type DatResponseObject = {
    alg: string,
    typ: "JWT",
    kid: string,
    access_token: DynamicAttributeToken,
    signature?: string
};

/** @see https://datatracker.ietf.org/doc/html/rfc7517#section-4 JSON Web Key (JWK) Format */
export type JsonWebKey = {
    kty: string,
    use?: "sig" | "enc",
    key_ops?: Array<"sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits">,
    alg?: string,
    kid?: string,
    x5u?: string,
    x5c?: Array<string>,
    x5t?: string,
    "x5t#S256"?: string,
    k?: string,
    n?: string,
    e?: string,
    d?: string,
    crv?: string,
    x?: string,
    y?: string,
    p?: string,
    q?: string,
    dp?: string,
    dq?: string,
    qi?: string
};

/** @see https://datatracker.ietf.org/doc/html/rfc7517#section-5 JWK Set Format */
export type JsonWebKeySet = {
    keys: Array<JsonWebKey>
};
