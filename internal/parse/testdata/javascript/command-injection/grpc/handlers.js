import {exec} from 'child_process';
export function ping(call,callback) {
 exec('ping -c 1 '+call.request.host,function(err,out){callback(null,{result:out})});
}
export function fixed(call,callback) {
 exec('uptime',function(err,out){callback(null,{result:out})});
}
