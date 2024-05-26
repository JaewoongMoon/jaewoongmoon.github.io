---
layout: post
title: "grpc-go에서 발생하는 use of closed network connection에러"
categories: [프로그래밍, Go]
tags: [프로그래밍, Go]
toc: true
---

# 배경
- PacketProxy를 사용해서 gRPC 통신을 MITM하려고 하는데, go로 만든 evans 클라이언트에서 다음과 같은 에러를 발생시켰다. 

```sh
# [OUTPUT]
evans: code = Unavailable, number = 14, message = "connection error: desc = \"error reading server preface: read tcp 127.0.0.1:54
485->127.0.0.1:9002: use of closed network connection\""
```

- 조금 구글 검색해보니 Go의 "net"패키지와 관련된 문제(버그?)라고 한다.  이미 닫힌 소켓에 데이터를 쓰거나 읽으려고 할 때 발생한다고 한다. (출처: https://castaneai.hatenablog.com/entry/2020/01/09/193539)

# 의심1. Go의 net 패키지 자체가 문제다. 
- 코드 수정으로 해결할 수 있는지 확인하기 위해서 Go의 net 패키지를 사용한 소켓 프로그램 샘플을 MITM해본다.  
- 만약 동일한 에러가 확인된다는 net 패키지 문제다. 
- 음...재현이 되지 않는다. MITM이 성공해버렸다. 
- Go의 net 패키지는 문제가 없어보인다. 

# 의심2. evans의 구현이 문제다. 

## 어프로치 1. 최신버전의 Go로 evans를 빌드해본다. 
- Go 버전 `go version go1.20.4 windows/amd64`로 새롭게 빌드해서 사용해봤지만 문제가 동일했다. 

## 어프로치 2. 다른 grpc 클라이언트 툴(grpcurl)로 테스트 
그렇다면 evans 이외에 다른 grpc 클라이언트 툴을 사용해서 해본다. 다른 후보로는 `grpcurl`이 있다. 참고로 이 툴도 Go로 개발되었다. 

```sh

cd D:\projects\grpc_sample_server\grpc\examples\python\helloworld
grpcurl -import-path ../../protos -proto helloworld.proto SayHello
Too few arguments.
Try 'C:\Users\N3799\go\bin\grpcurl.exe -help' for more details.

```

```sh
PS D:\projects\grpc_sample_server\grpc\examples\python\helloworld> grpcurl localhost:9001 --plaintext --import-path ../../protos --proto helloworld.proto SayHello
Too many arguments.
Try 'C:\Users\N3799\go\bin\grpcurl.exe -help' for more details.
```

참고 

```sh
grpcurl -v -plaintext -d '{"name":"bob"}' localhost:50051 protos.HelloWorld/SayHello

Error invoking method "protos.HelloWorld/SayHello": failed to query for service descriptor "protos.HelloWorld": server does not support the reflection API
```
(https://gist.github.com/miguelmota/e58df24b2fff889b8d7caa13ad658b37)


```
grpcurl -v -plaintext -d '{"name":"bob"}' localhost:50051  --plaintext --import-path ../../protos --proto helloworld.proto SayHello

grpcurl -v -plaintext localhost:50051 --import-path protos --proto helloworld.proto SayHello
grpcurl -v -plaintext --import-path protos --proto helloworld.proto　localhost:50051 SayHello
```

오 옵션을 먼저주니까 바꼈다. 

```
PS D:\projects\grpc_sample_server\grpc\examples> grpcurl -v -plaintext --import-path protos --proto helloworld.proto　localhost:50051 Greeter.SayHello
Error invoking method "Greeter.SayHello": target server does not expose service "Greeter"
```

grpcurl은 grpc의 리플렉션 기능이 활성화되어 있을 때만 사용가능한듯하다... 리플렉션 기능을 살펴보자. 


팀동료에 의하면 grpc-go 라이브러리에 의한 것. (Go grpc-hello 샘플을 사용해도 재현된다고 한다.)
https://github.com/grpc/grpc-go 

# 참고
- https://www.developer.com/languages/intro-socket-programming-go/
- https://github.com/grpc/grpc/blob/master/doc/server-reflection.md
