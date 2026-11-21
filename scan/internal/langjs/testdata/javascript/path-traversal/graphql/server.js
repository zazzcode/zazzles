import { ApolloServer } from '@apollo/server';
import typeDefs from './schema.graphql';
import { report, listed, fixed } from './resolvers.js';
new ApolloServer({ typeDefs, resolvers: { Query: { report, listed, fixed } } });
