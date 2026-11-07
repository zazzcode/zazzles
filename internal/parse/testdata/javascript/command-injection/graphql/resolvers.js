import {exec,execFile} from 'child_process';
export function ping(parent,args) {
 return exec('ping -c 1 '+args.host);
}
export function safe(parent,args) {
 if (args.host !== 'localhost') { throw new Error('rejected'); }
 return execFile('/bin/ping',['-c','1',args.host]);
}
export function fixed(parent,args) {
 return exec('uptime');
}
