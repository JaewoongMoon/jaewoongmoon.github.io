---
layout: post
title: "Python Mongodb 사용법"
categories: [프로그래밍]
tags: [프로그래밍, Python, Mongodb]
toc: true
last_modified_at: 2024-10-29 09:33:00 +0900
---

# 개요
- Python을 사용해서 Mongodb를 다루는 법을 정리해둔다.
- OS에 MongoDB가 설치되어 기본포트인 27017번 포트로 MongoDB가 서비스중인 상태이다. 
- MongoDB는 JSON 타입의 데이터를 다루는데 아주 궁합이 좋다. 

MongoDB와 RDBMS의 구성요소를 비교해보면 다음과 같다. MongoDB의 컬렉션(Collection)은 RDBMS의 테이블과 같은 개념이다. 

![](/images/RDBMS_MongoDB_Mapping.jpg)

출처: https://rastalion.dev/mongodb-collection-%EC%83%9D%EC%84%B1%ED%95%98%EA%B8%B0/

# 설치

```sh
python -m pip install pymongo
```

# 모듈 임포트하기 

```py
import pymongo
```

# DB 접속 클라이언트 생성하기

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")

mydb = myclient["mydatabase"] # 데이터베이스명을 지정한다. 

```

# 컬렉션 지정하기 

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]

mycol = mydb["customers"]
```

# 컬렉션에 데이터 삽입하기 

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["customers"]

mydict = { "name": "John", "address": "Highway 37" }

x = mycol.insert_one(mydict)
print(x.inserted_id) # id 필드 확인 
```

# 컬렉션에서 조건을 줘서 데이터 찾기

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["customers"]

for x in mycol.find({},{ "_id": 0, "name": 1, "address": 1 }):
  print(x)
```

# 컬렉션에서 조건을 줘서 데이터 찾기2 (쿼리 오브젝트 사용)

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["customers"]

myquery = { "address": { "$gt": "S" } }

mydoc = mycol.find(myquery)

for x in mydoc:
  print(x)
```

# 찾은 결과 정렬하기 

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["customers"]

mydoc = mycol.find().sort("name")

for x in mydoc:
  print(x)
```

# 컬렉션에서 데이터 삭제하기

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["customers"]

myquery = { "address": "Mountain 21" }

mycol.delete_one(myquery)
```


# 컬렉션에서 데이터 업데이트하기
- address 필드의 값을  "Valley 345" 에서 "Canyon 123" 로 업데이트한다. 

```py
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]
mycol = mydb["customers"]

myquery = { "address": "Valley 345" }
newvalues = { "$set": { "address": "Canyon 123" } }

mycol.update_one(myquery, newvalues)

#print "customers" after the update:
for x in mycol.find():
  print(x)
```


# 트러블슈팅
## pymongo.errors.CursorNotFound 에러가 발생할 때 
현상: PyMongo 사용중 다음과 같은 에러가 발생한다.   

```sh
pymongo.errors.CursorNotFound: cursor id 7073505406508033101 not found, full error: {'ok': 0.0, 'errmsg': 'cursor id 7073505406508033101 not found', 'code': 43, 'codeName': 'CursorNotFound'}
```

- 스택오버플로 (https://stackoverflow.com/questions/24199729/pymongo-errors-cursornotfound-cursor-id-not-valid-at-server) 를 읽어 보면, 10분이상 비활성(inactivate) 상태여서 타임아웃이 발생한 것이라고 한다. 
- 아마 처리가 10분이상 걸리는 작업이면 이 에러가 발생할 것 같기도 하다. 
- 몽고db의 collection 객체의 find 메서드 실행시에 `no_cursor_timeout=True` 옵션을 주면 해결된다고 한다. (처리가 끝나면 반드시 커서를 종료시켜야 한다.)

## 'update' command document too large 
하나의 도큐먼트의 사이즈가 너무 크면 저장할 수 없다. 

mongo 셸에서 다음 커맨드를 입력하면 현재 제한 사이즈를 볼 수 있다. 16MB로 되어 있었다. 아쉽지만 몽고DB에서 Document의 제한 사이즈는 변경할 수 없다는 것 같다. 

```sh
mongo
> db.isMaster().maxBsonObjectSize/(1024*1024)+' MB'
16 MB
```

# 참고: 윈도우즈에서 Mongo셸을 실행하고 싶을 때 
Mongo 셸의 바이너리는 "C:\Program Files\MongoDB\Server\5.0\bin\mongo.exe"에 설치되어 있다. 이 것을 실행한다. PATH 환경변수에 등록해두면 좋다. 

# 참고 URL
- https://www.w3schools.com/python/python_mongodb_getstarted.asp
- https://rastalion.dev/mongodb-collection-%EC%83%9D%EC%84%B1%ED%95%98%EA%B8%B0/