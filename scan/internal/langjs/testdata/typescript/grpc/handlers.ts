import {Sequelize} from 'sequelize';
const db=new Sequelize('sqlite::memory:');
export function shared(call:any,callback:any) {
 const request=call.request;
 return db.query('SELECT * FROM users WHERE email = '+request.email);
}
export function bound(call:any,callback:any) {
 const email=call.request.email;
 return db.query('SELECT * FROM users WHERE email = $email',{bind:{email}});
}
export function unknown(call:any,callback:any) {
 return db.query('SELECT '+transform(call.request.email));
}
function allowed(email:string) { return email === 'allowed@example.test'; }
export function guarded(call:any,callback:any) {
 if (!allowed(call.request.email)) { throw new Error('rejected'); }
 return shared(call,callback);
}
export function unknownGuard(call:any,callback:any) {
 guard(call.request.email);
 return db.query('SELECT '+call.request.email);
}
export function unused(call:any,callback:any) { callback(null,{result:'constant'}); }
