import {ApolloServer} from '@apollo/server';
import typeDefs from './schema.graphql';
import {shared,bound,unknown,guarded} from './resolvers.js';
const resolvers={
 Query:{raw:shared,bound,unknown,guarded,open:shared,wrapped:wrap(shared)},
 Mutation:{create:(parent,args)=>args.email},
 User:{lookup:shared}
};
new ApolloServer({typeDefs,resolvers});
