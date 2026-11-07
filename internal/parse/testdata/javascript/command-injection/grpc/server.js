import * as grpc from '@grpc/grpc-js';
import * as loader from '@grpc/proto-loader';
import {ping,fixed} from './handlers';
const definition=loader.loadSync('./search.proto');
const api=grpc.loadPackageDefinition(definition);
const server=new grpc.Server();
server.addService(api.fixtures.cmd.PingService.service,{ping,fixed});
