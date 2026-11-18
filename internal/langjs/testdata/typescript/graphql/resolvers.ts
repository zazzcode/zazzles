import {Sequelize} from 'sequelize';
const db = new Sequelize('sqlite::memory:');
export function shared(parent: unknown,args: {email: string},context: unknown,info: unknown) {
 return db.query('SELECT * FROM users WHERE email = '+args.email);
}
export function bound(parent: unknown,args: {email: string}) {
 const email=args.email;
 return db.query('SELECT * FROM users WHERE email = $email',{bind:{email}});
}
export function unknown(parent: unknown,args: {email: string}) {
 return db.query('SELECT '+transform(args.email));
}
export function guarded(parent: unknown,args: {email: string},context: unknown,info: unknown) {
 if (!allowed(args.email)) { throw new Error('rejected'); }
 return shared(parent,args,context,info);
}
function allowed(email) { return email === 'allowed@example.test'; }
