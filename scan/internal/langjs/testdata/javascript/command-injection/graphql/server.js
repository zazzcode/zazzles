import {ApolloServer} from '@apollo/server';
import typeDefs from './schema.graphql';
import {ping,safe,fixed} from './resolvers.js';
new ApolloServer({typeDefs,resolvers:{Query:{ping,safe,fixed}}});
