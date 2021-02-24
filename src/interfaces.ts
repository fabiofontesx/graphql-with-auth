export interface IJwk {
    alg: string;
    e: string;
    kid: string;
    kty: string;
    n: string;
    use: string;
}

export interface ICognitoTokenHeader {
    kid: string; 
    alg: string
}

export interface ICognitoTokenPayload { 
    sub: string;
    event_id: string;
    token_use: string;
    scope: string;
    auth_time: number;
    iss: string;
    exp: number;
    iat: number;
    jti: string;
    client_id: string;
    username: string;
}

export interface ICognitoDecodedToken {
    header: ICognitoTokenHeader,
    payload:ICognitoTokenPayload;
    signature: string;
}