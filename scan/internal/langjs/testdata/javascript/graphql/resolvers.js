import {Sequelize} from 'sequelize';
const db = new Sequelize('sqlite::memory:');
export function shared(parent,args,context,info) {
 return db.query('SELECT * FROM users WHERE email = '+args.email);
}
export function bound(parent,args) {
 const email=args.email;
 return db.query('SELECT * FROM users WHERE email = $email',{bind:{email}});
}
export function unknown(parent,args) {
 return db.query('SELECT '+transform(args.email));
}
export function guarded(parent,args,context,info) {
 if (!allowed(args.email)) { throw new Error('rejected'); }
 return shared(parent,args,context,info);
}
function allowed(email) { return email === 'allowed@example.test'; }
