---
layout: post
title: "서버교체후 MySQL Workbench 접속이 안되는 트러블 슈팅"
categories: [프로그래밍, MySQL Workbench]
tags: [프로그래밍,  MySQL Workbench, Docker]
toc: true
last_modified_at: 2024-08-30 14:55:00 +0900
---

# 개요
- MySQL Workbench 를 사용하면서 리모트에 위치한 MySQL 서버에 접속이 안되는 트러블이 있었기 때문에 해결방법을 정리해둔다. 
- 리모트 서버는 도커로 MySQL을 구동하고 있다. 포트는 호스트의 3306포트와 연결되어 있다. 
- 리모트 서버는 최근에 OS마이그레이션 작업을 실시해서 서버의 공개키에 변동이 있었다. 

# 현상
접속하려고 하면 다음과 같은 메세지가 적혀진 팝업이 뜬다. 팝업에는 OK버튼이 있다. 

```
Could not connect the SSH Tunnel   
WARNING: Server public key has changed. It means either you're under attack or the administrator has changed the key. New public fingerprint is: ...
```

OK 버튼을 누르면 다음과 같은 에러 팝업이 뜬다. 

```
Failed to Connect to MySQL at 127.0.0.1:3306 through SSH tunnel at ... 
```

# 해결방법
다음 커맨드로 오래된 호스트 키를 삭제하고 다시 Workbench를 구동해서 접속하면 된다. 

```sh
ssh-keygen -R {에러가발생한호스트도메인ORIP주소}
```

# 참고
트러블 슈팅시 참고가 될 정보도 적어둔다. 

## `ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2) 에러 
리모트 서버에 SSH로 접속해서 MySQL 클라이언트로 접속해보려고 할 때 위와 같은 에러가 발생했다. 이는 호스트를 접속하지 않았을 때 발생하는 에러다. 

- 다음과 같은 -h 옵션을 사용해서 호스트를 지정한다.
- MySQL을 도커 컨테이너로 구동하고 있는 경우 h옵션(host)을 써서 호스트 IP주소 지정이 필요한 것 같다. 

```sh
mysql -u {MYSQL_USERNAME} -h 127.0.0.1 -p 
```


## Could not connect the SSH Tunnel: Access denied for 'none'. Authentication that can continue: public key
MySQL Workbench에 설정한 접속용 개인키가 PEM 파일이 아닌 Putty에서 사용하는 ppk 파일로 지정되어 있을 때 발생한다. PEM파일을 지정해주면 해결된다. 