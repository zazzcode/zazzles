import * as grpc from '@grpc/grpc-js';
import * as loader from '@grpc/proto-loader';
import { fetch, fixed } from './handlers';
const definition = loader.loadSync('./reports.proto');
const api = grpc.loadPackageDefinition(definition);
const server = new grpc.Server();
server.addService(api.fixtures.files.ReportService.service, { fetch, fixed });
