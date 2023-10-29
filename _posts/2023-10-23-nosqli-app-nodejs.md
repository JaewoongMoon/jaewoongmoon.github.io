---
layout: post
title: "NoSQL 인젝션이 가능한 Node.js 앱 만들어보기"
categories: [보안취약점, NoSQL injecition]
tags: [보안취약점, NoSQL injecition, Node.js]
toc: true
last_modified_at: 2023-10-23 09:50:00 +0900
---

# 개요, 목적
- NoSQL인젝션이 가능한 Node.js 앱을 만들어본다. 
- 어떤 코드가 취약한지 어떻게 하면 방어할 수 있는지 알아본다. 

# 실습환경 준비
## 필요한 패키지 인스톨 
```sh
npm init -y
npm i express mongoose nodemon dotenv
```

## 웹 어플리케이션 코드 (app.js) 작성
프로젝트 루트에 코드를 작성한다. 
app.js를 다음과 같이 작성한다. 

```js
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const routes = require('./routes.js');

const app = express();

app.use(express.json());

app.use(routes);

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Mongoose connected 🍃');
    app.listen(3000, () => {
      console.log('Server is up and running 🚀');
    });
  })
  .catch((error) => {
    console.log(error);
  });

```

## DB 핸들링 코드 (user.model.js) 작성
user.model.js를 다음과 같이 작성한다. 

```js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
  },
  password: {
    type: String,
    unique: true,
  },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
```

## 웹 패스 핸들링 코드(routes.js) 작성
routes.js를 다음과 같이 작성한다. 

```js
const express = require('express');

const User = require('./user.model');

const router = express.Router();

router.get('/users', async (req, res, next) => {
  return res.json({
    users: await User.find({}).exec(),
  });
});

router.post('/login', async (req, res, next) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username, password }).exec();

  res.json({
    message: `Logged in as ${user.username}`,
  });
});

module.exports = router;
```

## DB구성
MongoDB에서 사용하고자 하는 DB를 작성한다.  나는 `local` DB에 `users`라는 컬렉션을 생성하고 몇 개의 유저정보를 삽입하였다. 

## .env작성
.env를 작성한다. 환경에 맞게 적절히 변경한다. 

```sh
MONGODB_URI=mongodb://localhost:27017/local
```

## package.json에 dev script추가 
package.json의 scripts 에 dev를 추가한다. dev를 지정해줄 시 `nodemon app.js`가 실행된다. (nodemon은 소스코드 수정을 모니터링해준다. 소스코드 수정할 시 바로바로 적용해준다. 서버를 일일히 재구동할 필요가 없어서 편리하다.)

```json
{
  "name": "nosqli_nodejs",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon app.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "express": "^4.18.2",
    "express-mongo-sanitize": "^2.2.0",
    "mongoose": "^7.6.3"
  },
  "devDependencies": {
    "dotenv": "^16.3.1",
    "nodemon": "^3.0.1"
  }
}

```

## 서버 구동

```sh
npm run dev
Mongoose connected 🍃
Server is up and running 🚀
```

## 로그인 테스트 
- 로그인을 테스트해본다. curl을 사용해서 Burp Suite로 캡쳐한다. 
- PC의 hosts파일을 수정해서 my-unsafeweb.com이 127.0.0.1로 연결되도록 DNS설정을 해둔다. (타겟 주소를 localhost로 하면 Burp Suite가 캡쳐를 하지 못한다.)

```sh
curl -X POST http://my-unsafeweb.com:3000/login -d '{"username":"moon", "password":"12345"}' -H "Content-Type: application/json" -x http://localhost:8080
```

Burp Suite에서 캡쳐한 HTTP 요청이다. 

```http
POST /login HTTP/1.1
Host: my-unsafeweb.com:3000
User-Agent: curl/8.0.1
Accept: */*
Content-Type: application/json
Content-Length: 39
Connection: close

{"username":"moon", "password":"12345"}
```

HTTP응답. 로그인에 성공했다. 

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 31
ETag: W/"1f-rvRDfuLuahQ9mLO31qUiKaMtBqs"
Date: Tue, 24 Oct 2023 05:13:33 GMT
Connection: close

{"message":"Logged in as moon"}
```

# 공격 실습 💉

패스워드에 오퍼레이터를 사용한다. `{ "$ne": null }`를 사용해서 null이 아닌 조건을 사용했다. 

```sh
curl -X POST http://my-unsafeweb.com:3000/login -d '{"username":"moon", "password": { "$ne": null }}' -H "Content-Type: application/json" -x http://localhost:8080
```


```htto
POST /login HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Content-Type: application/json
Content-Length: 64
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1


{
    "username": "moon",
    "password": { "$ne": null }
}
```

로그인이 된다! 😮 이 것으로 NoSQL 인젝션이 가능한 것을 알았다. 

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 31
ETag: W/"1f-rvRDfuLuahQ9mLO31qUiKaMtBqs"
Date: Mon, 23 Oct 2023 01:49:26 GMT
Connection: close

{"message":"Logged in as moon"}
```

# 방어 실습 🛡🧰
## 새니타이즈를 사용한 방어

1. mongoSanitize를 설치한다. 

```sh
npm i express-mongo-sanitize
```

2. app.js의 코드를 다음과같이 개선한다.  
- mongoSanitize를 추가하여 요청 파라메터 새니타이즈를 구현하였다. 

```javascript
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const routes = require('./routes.js');

const app = express();

app.use(express.json());

//app.use(routes); // 취약한 코드 

app.use(
    mongoSanitize({
      onSanitize: ({ req, key}) => {
        console.log(key);
      },
    }),
    routes
);

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Mongoose connected 🍃');
    app.listen(3000, () => {
      console.log('Server is up and running 🚀');
    });
  })
  .catch((error) => {
    console.log(error);
  });
```

그러면 `{"username": "moon","password": { "$ne": null }}` 와 같은 페이로드를 송신했을 때 다음과 같이 `UnhandledPromiseRejectionWarning: CastError` 에러 메세지를 출력하면서 로그인이 되지 않는다. 서버측으로부터는 응답이 오지 않는다.  (=> 뭔가 에러를 핸들링한 후에 다시 리다이렉트 시킨더가 하는 코드가 필요하다. )

```sh
body
(node:18492) UnhandledPromiseRejectionWarning: CastError: Cast to string failed for value "{}" (type Object) at path "password" for model "User"
...  
```

## Parameterized Query를 사용한 방어
- MongoDB에서 Parameterized Query란 미리 오퍼레이터가 정의된 쿼리를 의미하는 것 같다. 
- 예를들어 routes.js의 로그인부분 코드가 다음과 같이 되어 있는 경우다. 
- username과 password에 이미 `$eq` 오퍼레이터가 들어가 있다. 

```js
router.post('/login', async (req, res, next) => {
  const { username, password } = req.body;
  // const user = await User.findOne({ username, password }).exec(); //이전 코드 
  const query = { username: {$eq: username}, password: { $eq: password } };
  const user = await User.findOne(query).exec();

  res.json({
    message: `Logged in as ${user.username}`,
  });

});
```

`{"username": "moon","password": { "$ne": null }}` 을 보내보면 다음과 같은 에러가 발생한다. 

```sh
(node:18748) UnhandledPromiseRejectionWarning: CastError: Cast to string failed for value "{ '$ne': null }" (type Object) at path "password" for model "User"
...
```

## 궁금점
### Javascript 인젝션에 대해서 
- NoSQL인젝션 수행시에 어떻게 Javascript코드 인젝션도 가능한가? (왜 MongoDB에서 javascript 코드를 평가하는가?)

### 새니타이즈이외의 다른 방어수단은?
- 새니타이즈 이외의 방어수단은 없는가? 예를들어 일반적인 SQL인젝션처럼 바인드 기구(Prepared Statement)를 사용하는 등의 방법은 없는가? [여기][https://ritikchourasiya.medium.com/preventing-mongodb-nosql-injection-attacks-securing-your-node-js-56215ef7455]를 보면 NoSQL인젝션 방어방법으로 새니타이즈와 더블어 Prepared Statement 또는 Parameterized Query를 소개하고 있다. Prepared Statement에 대해서는 검색해봐도 정보가 나오지 않는다. 아마도 MongoDB에는 Prepared Statement가 존재하지 않는 것 같다. 


# 참고
- https://berkegokmen1.medium.com/your-nodejs-app-is-probably-vulnerable-to-nosql-injection-attacks-69e6acba7b65
- https://www.npmjs.com/package/express-mongo-sanitize
- https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf
- https://ritikchourasiya.medium.com/preventing-mongodb-nosql-injection-attacks-securing-your-node-js-56215ef7455