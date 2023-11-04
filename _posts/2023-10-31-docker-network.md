---
layout: post
title: "Docker 네트워크 정리"
categories: [Docker, Container]
tags: [Docker, Container]
toc: true
last_modified_at: 2023-10-31 14:55:00 +0900
---


# 배경
- 취약점을 POC할 때 로컬PC에 Docker 컨테이너를 여러개 구동할 필요가 있다.
- 공격측 컨테이너와 타겟측 컨테이너등을 별도로 구축하는 경우 등이다. 
- 이 때 컨테이너들 사이에 통신(주로 HTTP통신)을 할 필요가 있다. 
- 타겟서버는 호스트는와 포트를 공유하므로 호스트 입장에서 봤을 때 localhost:포트번호로 접속할 수 있다. 
- 문제는 공격측에서 타겟 컨테이너에 접속할 때이다. 

# 상황
- 호스트에서는 localhost:3001 로 웹 서버를 구동하고 있다. 
- 컨테이너에서 localhost:3001로 curl을 요청하면 연결되지 않는다. (컨테이너는 구동시에 --net host 옵션을 줬으므로 호스트와 동일한 네트워크에서 동작한다고 상정한다. )
- 처음에는 localhost자체가 127.0.0.1로 이름 해결이 안되는 것으로 판단했지만 curl 127.0.0.1:3001 도 동작하지 않으므로 DNS문제는 아닌 것으로 보인다. 

# 확인
## Telnet 이나 Ping으로 확인해보기 
telnet으로 확인해보니 3001포트로 접속이 된다! 오호... 그렇다면 curl의 설정이 뭔가 문제가 있는 것 같다. 

```sh
telnet 127.0.0.1 3001
Connected to 127.0.0.1
```

## 해결
-v 옵션(디버그 옵션)으로 실행해보고 원인을 알았다. localhost인데도 프록시 서버에 연결하고 있었다. 다음과 같이 명시적으로 프록시를 공백으로 주는 것으로 해결하였다. 

```sh
curl -x "" http://localhost:3001
```

또는 다음과 같이 해도 된다. 

```sh
curl --noproxy localhost http://localhost:3001
```

또는 다음과 같이 환경변수를 먼저 지정해준뒤에 실행해도 된다. 

```sh
no_proxy=127.0.0.1,localhost
curl http://localhost:3001
```