// SferaDating server. Запуск: npm i express ws better-sqlite3 bcryptjs jsonwebtoken express-rate-limit
// OWNER_EMAIL=dimamix2306@gmail.com JWT_SECRET=длинная_строка BASE_URL=https://ваш-сайт ORIGIN=https://ваш-сайт node server.js
const express=require('express'),http=require('http'),path=require('path'),{WebSocketServer}=require('ws'),Db=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),rl=require('express-rate-limit'),crypto=require('crypto');
const OWNER=(process.env.OWNER_EMAIL||'dimamix2306@gmail.com').toLowerCase(),SECRET=process.env.JWT_SECRET||crypto.randomBytes(32).toString('hex'),BASE=process.env.BASE_URL||'http://localhost:3000';
const db=new Db(process.env.DB_PATH||'sfera.db');db.pragma('journal_mode=WAL');
db.exec(`create table if not exists users(id integer primary key,email text unique,hash text,age int,role text default 'user',ver int default 0,vt text,blue int default 0,mute int default 0,ban int default 0,warns int default 0,calls int default 0,created int,seen int);
create table if not exists prof(uid int primary key,name,photo,city,bio,hobbies,goal,gender,phone,hidden int default 0,views int default 0,pub int);
create table if not exists lk(a int,b int,k text,primary key(a,b,k));
create table if not exists msg(id integer primary key,a int,b int,body text,t int,rd int default 0);
create table if not exists blk(a int,b int,primary key(a,b));
create table if not exists rep(id integer primary key,f int,tg int,reason text,txt text,t int);
create table if not exists lab(uid int,l text,primary key(uid,l));
create table if not exists log(id integer primary key,actor int,act text,tg int,t int);`);
let mail=null;try{if(process.env.SMTP_URL)mail=require('nodemailer').createTransport(process.env.SMTP_URL)}catch{}
const send=(to,sub,text)=>mail?mail.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER||'SferaDating <no-reply@localhost>',to,subject:sub,text}).catch(console.error):console.log('ПИСЬМО',to,sub,text);
const now=()=>Date.now(),grp=a=>a>=18?1:0,q1=(s,...a)=>db.prepare(s).get(...a),qa=(s,...a)=>db.prepare(s).all(...a),run=(s,...a)=>db.prepare(s).run(...a);
const role=u=>u.email===OWNER&&u.ver?'owner':u.role; // владелец только по ПОДТВЕРЖДЁННОМУ email, проверка на сервере
const A=express(),srv=http.createServer(A);A.use(express.json({limit:'600kb'}));
A.use((q,s,n)=>{s.set({'Access-Control-Allow-Origin':process.env.ORIGIN||'*','Access-Control-Allow-Headers':'Content-Type,Authorization','Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS'});q.method==='OPTIONS'?s.end():n()});
const auth=(q,s,n)=>{try{const p=jwt.verify((q.headers.authorization||'').slice(7),SECRET),u=q1('select * from users where id=?',p.id);if(!u||u.ban||(u.age<18&&u.email!==OWNER))return s.status(401).json({e:'Войдите заново'});u.role=role(u);q.u=u;run('update users set seen=? where id=?',now(),u.id);n()}catch{s.status(401).json({e:'Войдите заново'})}};
const need=(...r)=>(q,s,n)=>r.includes(q.u.role)?n():s.status(403).json({e:'Нет доступа'});
const C=new Map(),push=(id,o)=>(C.get(id)||[]).forEach(w=>w.send(JSON.stringify(o)));
const blocked=(a,b)=>q1('select 1 x from blk where (a=? and b=?)or(a=? and b=?)',a,b,b,a);
const can=(u,id)=>{const o=q1('select * from users where id=?',id);return o&&!o.ban&&o.id!==u.id&&grp(o.age)===grp(u.age)&&!blocked(u.id,id)&&o}; // взрослые и несовершеннолетние разделены на сервере
const logA=(a,act,t)=>run('insert into log(actor,act,tg,t)values(?,?,?,?)',a,act,t,now());
const lim=(m,x)=>rl({windowMs:m*6e4,max:x,message:{e:'Слишком много попыток, подождите'}});

A.post('/api/register',lim(60,10),(q,s)=>{const{email,password,age}=q.body,e=String(email||'').toLowerCase().trim();
 if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)||String(password||'').length<8||!(age>=18&&age<=100))return s.status(400).json({e:'Регистрация только с 18 лет. Проверьте email и пароль (от 8 символов)'});
 if(q1('select 1 x from users where email=?',e))return s.status(409).json({e:'Этот email уже зарегистрирован'});
 const vt=crypto.randomBytes(24).toString('hex');const auto=!mail&&e!==OWNER?1:0; // без SMTP обычные пользователи подтверждаются сразу; email создателя — только по ссылке из логов
 run('insert into users(email,hash,age,ver,vt,created,seen)values(?,?,?,?,?,?,?)',e,bcrypt.hashSync(password,12),age|0,auto,auto?null:vt,now(),now());
 if(!auto)send(e,'Подтверждение SferaDating','Подтвердите email: '+`${BASE}/api/verify?t=${vt}`);s.json({ok:1})});
A.get('/api/verify',(q,s)=>{const r=run("update users set ver=1,vt=null where vt=? and vt not like 'r%'",String(q.query.t||''));s.send(r.changes?'Email подтверждён. Можно вернуться на сайт.':'Ссылка недействительна')});
A.post('/api/login',lim(15,10),(q,s)=>{const u=q1('select * from users where email=?',String(q.body.email||'').toLowerCase().trim());
 if(!u||!bcrypt.compareSync(String(q.body.password||''),u.hash))return s.status(401).json({e:'Неверный email или пароль'});
 if(u.ban)return s.status(403).json({e:'Аккаунт заблокирован'});if(u.age<18&&u.email!==OWNER)return s.status(403).json({e:'SferaDating доступна только с 18 лет'});s.json({token:jwt.sign({id:u.id},SECRET,{expiresIn:'7d'})})});
A.post('/api/forgot',lim(15,5),(q,s)=>{const t='r'+crypto.randomBytes(24).toString('hex');run('update users set vt=? where email=?',t,String(q.body.email||'').toLowerCase());send(String(q.body.email||'').toLowerCase(),'Сброс пароля SferaDating','Ссылка для сброса: '+`${BASE}/?reset=${t}`);s.json({ok:1})});
A.post('/api/reset',lim(15,5),(q,s)=>{if(String(q.body.password||'').length<8)return s.status(400).json({e:'Пароль от 8 символов'});const r=run("update users set hash=?,vt=null,ver=1 where vt=? and vt like 'r%'",bcrypt.hashSync(q.body.password,12),String(q.body.t||''));r.changes?s.json({ok:1}):s.status(400).json({e:'Ссылка недействительна'})});
A.get('/api/me',auth,(q,s)=>{const u=q.u;s.json({id:u.id,email:u.email,age:u.age,role:u.role,ver:u.ver,calls:u.calls,mute:u.mute>now(),hasProfile:!!q1('select 1 x from prof where uid=?',u.id),profile:q1('select * from prof where uid=?',u.id)})});

const card=r=>({id:r.uid,name:r.name,photo:r.photo,city:r.city,bio:r.bio,hobbies:r.hobbies,goal:r.goal,age:r.age,blue:!!r.blue,pub:r.pub,views:r.views,labels:qa('select l from lab where uid=?',r.uid).map(x=>x.l),likes:q1("select count(*) c from lk where b=? and k='like'",r.uid).c,favs:q1("select count(*) c from lk where b=? and k='fav'",r.uid).c}); // телефон и email НЕ отдаются
A.post('/api/profile',auth,(q,s)=>{const b=q.body,u=q.u,n=String(b.name||'').trim().slice(0,40),c=String(b.city||'').trim().slice(0,60),bio=String(b.bio||'').trim().slice(0,500);
 if(!n||!c||!bio||!/^data:image\/(jpeg|png|webp);base64,/.test(b.photo||'')||b.photo.length>450000)return s.status(400).json({e:'Нужны фото (до 300 КБ), имя, город и описание'});
 let g=String(b.goal||'friends');if(!['friends','interests','games','chat','romance'].includes(g)||(u.age<18&&g==='romance'))g='friends';
 run('insert into prof(uid,name,photo,city,bio,hobbies,goal,gender,phone,pub)values(?,?,?,?,?,?,?,?,?,?) on conflict(uid) do update set name=excluded.name,photo=excluded.photo,city=excluded.city,bio=excluded.bio,hobbies=excluded.hobbies,goal=excluded.goal,gender=excluded.gender,phone=excluded.phone',u.id,n,b.photo,c,bio,String(b.hobbies||'').slice(0,200),g,String(b.gender||'').slice(0,10),String(b.phone||'').slice(0,20),now());s.json({ok:1})});
A.get('/api/feed',auth,(q,s)=>{const f=q.query,u=q.u,a=[u.id,grp(u.age),u.id,u.id];
 let sql='select p.*,u.age,u.blue from prof p join users u on u.id=p.uid where p.uid!=? and p.hidden=0 and u.ban=0 and (u.age>=18)=? and p.uid not in(select b from blk where a=?) and p.uid not in(select a from blk where b=?)';
 if(f.min){sql+=' and u.age>=?';a.push(+f.min)}if(f.max){sql+=' and u.age<=?';a.push(+f.max)}if(f.city){sql+=' and p.city like ?';a.push('%'+f.city+'%')}
 if(f.goal){sql+=' and p.goal=?';a.push(f.goal)}if(f.q){sql+=' and (p.hobbies like ? or p.bio like ?)';a.push('%'+f.q+'%','%'+f.q+'%')}if(f.blue==='1')sql+=' and u.blue=1';
 if(f.fav==='1')sql+=" and p.uid in(select b from lk where a="+(u.id|0)+" and k='fav')";
 s.json(qa(sql+' order by p.pub desc limit 60',...a).map(card))});
A.get('/api/user/:id',auth,(q,s)=>{if(!can(q.u,+q.params.id))return s.status(404).json({e:'Нет анкеты'});const r=q1('select p.*,u.age,u.blue from prof p join users u on u.id=p.uid where p.uid=?',+q.params.id);if(!r)return s.status(404).json({e:'Нет анкеты'});run('update prof set views=views+1 where uid=?',r.uid);s.json(card(r))});
A.post('/api/react/:id/:k',auth,(q,s)=>{const id=+q.params.id,k=q.params.k;if(!['like','heart','fav'].includes(k)||!can(q.u,id))return s.status(400).json({e:'Недоступно'});
 const h=q1('select 1 x from lk where a=? and b=? and k=?',q.u.id,id,k);if(h)run('delete from lk where a=? and b=? and k=?',q.u.id,id,k);else{run('insert into lk values(?,?,?)',q.u.id,id,k);if(k!=='fav')push(id,{type:'note',text:k==='like'?'Вам поставили лайк':'Вам отправили сердечко'})}s.json({on:!h})});
// Сообщения: писать можно без взаимных лайков; нужна подтверждённая почта, отсутствие мута/блока, одна возрастная группа
A.post('/api/msg/:id',auth,(q,s)=>{const id=+q.params.id,b=String(q.body.body||'').trim().slice(0,2000),u=q.u;
 if(!u.ver)return s.status(403).json({e:'Сначала подтвердите email'});if(u.mute>now())return s.status(403).json({e:'Вам временно ограничена отправка сообщений'});
 if(!b||!can(u,id))return s.status(400).json({e:'Сообщение недоступно'});run('insert into msg(a,b,body,t)values(?,?,?,?)',u.id,id,b,now());push(id,{type:'msg',from:u.id});s.json({ok:1})});
A.get('/api/msgs/:id',auth,(q,s)=>{const id=+q.params.id,u=q.u;run('update msg set rd=1 where a=? and b=?',id,u.id);s.json(qa('select id,a,body,t,rd from msg where (a=? and b=?)or(a=? and b=?) order by t limit 300',u.id,id,id,u.id))});
A.delete('/api/msg/:id',auth,(q,s)=>{run('delete from msg where id=? and a=?',+q.params.id,q.u.id);s.json({ok:1})});
A.get('/api/chats',auth,(q,s)=>{const u=q.u;s.json(qa(`select p.uid id,p.name,p.photo,(select body from msg m where (m.a=? and m.b=p.uid)or(m.a=p.uid and m.b=?) order by t desc limit 1) last,(select count(*) from msg m where m.a=p.uid and m.b=? and m.rd=0) unread from prof p where p.uid in(select b from msg where a=? union select a from msg where b=?) and p.uid not in(select b from blk where a=?)`,u.id,u.id,u.id,u.id,u.id,u.id))});
A.post('/api/block/:id',auth,(q,s)=>{run('insert or ignore into blk values(?,?)',q.u.id,+q.params.id);s.json({ok:1})}); // блок работает для любых диалогов
A.post('/api/settings',auth,(q,s)=>{run('update users set calls=? where id=?',q.body.calls?1:0,q.u.id);if('hidden' in q.body)run('update prof set hidden=? where uid=?',q.body.hidden?1:0,q.u.id);s.json({ok:1})});
A.delete('/api/me',auth,(q,s)=>{const i=q.u.id;for(const t of['prof where uid','users where id','msg where a=%d or b','lk where a=%d or b','blk where a=%d or b','lab where uid'])run('delete from '+t.replace('%d',i)+'=?',i);s.json({ok:1})});

A.post('/api/report/:id',auth,(q,s)=>{const id=+q.params.id,u=q.u,R=['Спам','Мошенничество','Скам','Оскорбления','Подозрительный аккаунт','Фальшивое фото','Неприемлемое поведение','Другое'];
 if(id===u.id||!R.includes(q.body.reason))return s.status(400).json({e:'Укажите причину'});
 if(q1('select 1 x from rep where f=? and tg=? and t>?',u.id,id,now()-864e5))return s.status(429).json({e:'Вы уже жаловались на этого пользователя'});
 run('insert into rep(f,tg,reason,txt,t)values(?,?,?,?,?)',u.id,id,q.body.reason,String(q.body.txt||'').slice(0,500),now());
 // уникальные жалобщики: подтверждённые аккаунты старше суток (защита от накрутки)
 const n=q1('select count(distinct r.f) c from rep r join users x on x.id=r.f where r.tg=? and x.ver=1 and x.created<?',id,now()-864e5).c,t=q1('select * from users where id=?',id);
 if(n>10&&t&&t.mute<now()&&t.email!==OWNER){run('update users set mute=? where id=?',now()+6048e5,id);logA(0,'auto_mute_7d',id);qa("select id from users where email=?",OWNER).forEach(o=>push(o.id,{type:'note',text:`Авто-мут на 7 дней: пользователь #${id} (${n} жалоб)`}))}
 s.json({ok:1})});

const OW=['blue','unblue','admin','unadmin','mod','unmod','delprof'],AD=['ban','unban','mute','unmute','warn','label','unlabel'],MO=['mute','warn'],LB=['Спам','Скам','Мошенник','Бот','Рекомендован','Подозрительный'];
const S={ban:'update users set ban=1 where id=?',unban:'update users set ban=0 where id=?',mute:`update users set mute=${now()+6048e5} where id=?`,unmute:'update users set mute=0 where id=?',warn:'update users set warns=warns+1 where id=?',blue:'update users set blue=1 where id=?',unblue:'update users set blue=0 where id=?',admin:"update users set role='admin' where id=?",unadmin:"update users set role='user' where id=?",mod:"update users set role='mod' where id=?",unmod:"update users set role='user' where id=?",delprof:'delete from prof where uid=?'};
const ST=['owner','admin','mod'];
A.post('/api/admin/act',auth,need(...ST),(q,s)=>{const u=q.u,i=q.body.id,t=/@/.test(i)?q1('select * from users where email=?',String(i).toLowerCase()):q1('select * from users where id=?',+i),act=q.body.act;
 const ok=u.role==='owner'?OW.concat(AD):u.role==='admin'?AD:MO;if(!t)return s.status(404).json({e:'Пользователь не найден'});
 if(!ok.includes(act)||t.email===OWNER)return s.status(403).json({e:'Недостаточно прав'});
 if(act==='label'||act==='unlabel'){if(!LB.includes(q.body.l))return s.status(400).json({e:'Нет такой метки'});run(act==='label'?'insert or ignore into lab values(?,?)':'delete from lab where uid=? and l=?',t.id,q.body.l)}
 else if(act==='mute'&&u.role!=='owner'&&false){}else run(S[act].replace(/mute=\d+/,'mute='+(now()+6048e5)),t.id);
 logA(u.id,act+(q.body.l?':'+q.body.l:''),t.id);s.json({ok:1})});
A.get('/api/admin/stats',auth,need(...ST),(q,s)=>{const c=x=>q1(x).c;s.json({users:c('select count(*) c from users'),online:q1('select count(*) c from users where seen>?',now()-3e5).c,fresh:q1('select count(*) c from users where created>?',now()-864e5).c,banned:c('select count(*) c from users where ban=1'),reports:c('select count(*) c from rep'),profiles:c('select count(*) c from prof'),msgs:c('select count(*) c from msg')})}); // только счётчики, без текста переписок
A.get('/api/admin/users',auth,need(...ST),(q,s)=>{const t='%'+String(q.query.q||'')+'%';s.json(qa('select id,email,age,role,ban,mute,warns,blue from users where email like ? or cast(id as text)=? order by id desc limit 50',t,String(q.query.q||'')))});
A.get('/api/admin/reports',auth,need(...ST),(q,s)=>s.json(qa('select r.id,r.tg,r.f,r.reason,r.txt,r.t,(select count(distinct f) from rep where tg=r.tg) uniq from rep r order by r.t desc limit 100')));
A.get('/api/admin/log',auth,need(...ST),(q,s)=>s.json(qa('select * from log order by t desc limit 100')));

A.get('/',(q,s)=>s.sendFile(path.join(__dirname,'index.html')));
// WebSocket: уведомления, новые сообщения и сигналы звонков (WebRTC)
new WebSocketServer({server:srv,path:'/ws'}).on('connection',(w,rq)=>{let u;try{const p=jwt.verify(new URL(rq.url,'http://x').searchParams.get('t'),SECRET);u=q1('select * from users where id=?',p.id)}catch{}
 if(!u||u.ban)return w.close();(C.get(u.id)||C.set(u.id,[]).get(u.id)).push(w);w.on('close',()=>C.set(u.id,(C.get(u.id)||[]).filter(x=>x!==w)));
 w.on('message',m=>{try{const d=JSON.parse(m);if(d.type!=='call')return;const me=q1('select * from users where id=?',u.id),o=can(me,+d.to);
  // звонок: только если чат уже начат И у обоих в настройках включены звонки
  if(!o||!me.calls||!o.calls||!q1('select 1 x from msg where (a=? and b=?)or(a=? and b=?)',me.id,o.id,o.id,me.id))return w.send(JSON.stringify({type:'note',text:'Звонок недоступен: нужен начатый чат и включённые звонки у обоих'}));
  push(o.id,{type:'call',from:me.id,data:d.data})}catch{}})});
srv.listen(process.env.PORT||3000,()=>console.log('SferaDating на порту',process.env.PORT||3000));
