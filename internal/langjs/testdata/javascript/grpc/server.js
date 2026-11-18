import * as grpc from '@grpc/grpc-js';
import * as loader from '@grpc/proto-loader';
import {shared,bound,unknown,guarded,unknownGuard,unused} from './handlers';
const definition=loader.loadSync('./search.proto');
const api=grpc.loadPackageDefinition(definition);
const server=new grpc.Server();
server.addService(api.fixtures.search.SearchService.service,{
 raw:shared,bound,unknown,guarded,open:shared,unknownGuard,unused,
 clientStream:shared,serverStream:shared,bidi:shared
});
