import { ApolloServer, AuthenticationError, gql } from 'apollo-server';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import jwkToPem from 'jwk-to-pem';
import path from 'path';

console.log(`test`);
console.log(`test2`);
import { ICognitoDecodedToken, ICognitoTokenPayload, IJwk } from './interfaces';
const typeDefs = gql`
  # Comments in GraphQL strings (such as this one) start with the hash (#) symbol.

  # This "Book" type defines the queryable fields for every book in our data source.
  type Book {
    title: String
    author: String
  }

  # The "Query" type is special: it lists all of the available queries that
  # clients can execute, along with the return type for each. In this
  # case, the "books" query returns an array of zero or more Books (defined above).
  type Query {
    books: [Book]
  }
`;

const books = [
    {
        title: 'The Awakening',
        author: 'Kate Chopin',
    },
    {
        title: 'City of Glass',
        author: 'Paul Auster',
    },
];

// Resolvers define the technique for fetching the types defined in the
// schema. This resolver retrieves books from the "books" array above.
const resolvers = {
    Query: {
        books: () => books,
    },
};

//COGNITO VERIFY EXAMPLE AMAZON https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.ts
const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: async ({ req }) => {
        const token = req.headers?.authorization?.split(' ')[1];
        if (!token) {
            throw new AuthenticationError('Missing token')
        }
        const decodedToken = jwt.decode(token, { complete: true, json: true }) as ICognitoDecodedToken;
        const jwksFile = fs.readFileSync(path.join(__dirname, '..', 'jwks.json'));
        const jwks = JSON.parse(jwksFile.toString()) as IJwk[];
        const currentJwk = jwks.find((jwk) => jwk.kid === decodedToken?.header.kid) as jwkToPem.JWK;

        if (!currentJwk) {
            throw new AuthenticationError('Chave não encontrada');
        }

        const pem = jwkToPem(currentJwk);
        const claim = jwt.verify(token, pem, { algorithms: ['RS256'] }) as ICognitoTokenPayload;
        const currentSeconds = Math.floor(new Date().valueOf() / 1000);
        if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
            throw new AuthenticationError('Token expirado')
        }

        const cognitoIssuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_7NYk2C8JP`;
        if (claim.iss !== cognitoIssuer) {
            throw new AuthenticationError('Issuer invalido')
        }

        if (claim.token_use !== 'access') {
            throw new AuthenticationError('Uso do token invalido')
        }
    }
})

server.listen(3300)
    .then(({ url }) => {
        console.log(`Listening at ${url} 🚀🚀🚀`)
    });