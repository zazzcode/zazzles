import {Sequelize} from 'sequelize';
const db=new Sequelize('sqlite::memory:');
export function shared(call,callback) {
 const request=call.request;
 return db.query('SELECT * FROM users WHERE email = '+request.email);
}
export function bound(call,callback) {
 const email=call.request.email;
 return db.query('SELECT * FROM users WHERE email = $email',{bind:{email}});
}
export function unknown(call,callback) {
 return db.query('SELECT '+transform(call.request.email));
}
function allowed(email) { return email === 'allowed@example.test'; }
export function guarded(call,callback) {
 if (!allowed(call.request.email)) { throw new Error('rejected'); }
 return shared(call,callback);
}
export function unknownGuard(call,callback) {
 guard(call.request.email);
 return db.query('SELECT '+call.request.email);
}
export function unused(call,callback) { callback(null,{result:'constant'}); }
