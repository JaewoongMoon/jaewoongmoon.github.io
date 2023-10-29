

# 개요
Mongodb 셸 커맨드를 정리해둔다. 

# 시스템 커맨드
OS의 셸에서 사용가능한 커맨드이다. 

## 몽고DB 접속

```sh
mongo
```

## 몽고DB 서비스 시작

```sh
mongod
```

## 몽고DB 서비스 종료

```sh
mongod --shutdown
```

# 몽고 셸 커맨드 
이하는 몽고 셸에 접속한 후에 사용가능한 커맨드들이다. 

## 데이터베이스 사용
만약 기존에 존재하지 않는 데이터베이스였다면 새롭게 생성한다. 

```sh
use [데이터베이스명]
```

## 컬렉션 관련 
컬렉션은 RDB의 테이블과 같은 의미인 것 같다.

### 모든 컬렉션 출력하기 

```sh
db.getCollectionNames()
```

### CRUD

```sh
db.[컬렉션명].save({type: “BlahBlah”})
db.[컬렉션명].find({type: “BlahBlah”})
db.[컬렉션명].update({type: “BlahBlah”}, {type: “BlahBlah2”})
db.[컬렉션명].remove({type: “BlahBlah”})
```

### 모든 데이터 삭제

```sh
db.[컬렉션명].remove({})
```

# 참고 
- https://www.mongodb.com/docs/manual/reference/command/