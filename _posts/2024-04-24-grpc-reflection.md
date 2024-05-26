---
layout: post
title: "grpc 리플렉션 개념"
categories: [프로그래밍, Go]
tags: [프로그래밍, Go]
toc: true
---

# 개요
- gRPC의 리플렉션(reflection) 개념을 정리한다.

# gRPC 리플렉션이란
- proto 파일이 없어도 grpc서버의 기능을 사용할 수 있게 해준다. 
- 주로 디버깅 목적으로 많이 쓰인다. (grpcurl에서 많이 쓴다.)
- REST API의 Open API 스펙 문서 페이지나, graphql의 introspection과 비슷한 개념이다. 
- 서버의 API(RPC)가 어떤 스펙으로 되어 있는지 친절하게 알려주는 기능이다.
- 프로덕션 환경과 같은 곳에서는 보안을 위해서 당연히 OFF로 해두는 게 좋다. 

# gRPC 리플렉션 기능 사용하기
- gRPC 리플렉션 기능을 사용하려면 Go기준으로 서버측의 코드에 `reflection.Register(s)`를 추가해주면 된다고 한다. 

```go
func main() {
    flag.Parse()
    lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    fmt.Printf("server listening at %v\n", lis.Addr())

    s := grpc.NewServer()

    // Register Greeter on the server.
    hwpb.RegisterGreeterServer(s, &hwServer{})

    // Register RouteGuide on the same server.
    ecpb.RegisterEchoServer(s, &ecServer{})

    // Register reflection service on gRPC server.
    reflection.Register(s) // 이 부분이다.

    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

# gRPC 리플렉션의 API 정의
- 리플렉션 기능 자체도 gRPC 서비스로서 구현되어 있다. 
- [여기](https://github.com/grpc/grpc/blob/master/src/proto/grpc/reflection/v1alpha/reflection.proto)에서 gRPC 리플렉션 서비스의 proto정의파일을 볼 수 있다. 

# gRPC 리플렉션 기능 테스트 
## gRPC 클라이언트 툴 evans를 리플렉션 모드로 기동 
- evans에 -r 옵션을 주면 리플렉션 모드로 기동할 수 있다. 
- localhost:50051 에 리플렉션 기능을 켠 서버가 동작중이다.
- 패키지 `grpc.reflection.v1alpha`에서 서비스 `ServerReflection`을 선택하고, `ServerReflectionInfo` 메서드를 호출한다. 

```sh
> evans -r --port 50051

  ______
 |  ____|
 | |__    __   __   __ _   _ __    ___
 |  __|   ' ' / /  / _. | | '_ '  / __|
 | |____   ' V /  | (_| | | | | | '__ ,
 |______|   '_/    '__,_| |_| |_| |___/

 more expressive universal gRPC client


helloworld.Greeter@127.0.0.1:50051> package grpc.reflection.v1alpha

grpc.reflection.v1alpha@127.0.0.1:50051> service ServerReflection

grpc.reflection.v1alpha.ServerReflection@127.0.0.1:50051> call ServerReflectionInfo
```

## 노출(expose)된 서비스 조사
- 호스트에 `localhost`를 입력하면 다음과 같이 어떤 기능을 사용할 것인지 물어본다. 먼저 노출된 서비스명을 조사하기 위해 `list_services`를 선택한다. 

```sh
  > file_by_filename
    file_containing_symbol
    file_containing_extension
    all_extension_numbers_of_type
    list_services

```

두 가지 서비스 `grpc.reflection.v1alpha.ServerReflection`와 `helloworld.Greeter`가 노출되어 있는 것을 알 수 있다. 

```sh
...snip...

host (TYPE_STRING) => localhost
v list_services
list_services (TYPE_STRING) =>
host (TYPE_STRING) => {
  "list_services_response": {
    "service": [
      {
        "name": "grpc.reflection.v1alpha.ServerReflection"
      },
      {
        "name": "helloworld.Greeter"
      }
    ]
  }
}
```

## 서비스에서 사용할 수 있는 메서드 조사 
- `file_containing_symbol`을 사용한다. 
- 심볼은 `helloworld.Greeter`를 입력한다. 
- 그러면 base64로 인코딩된 FileDescriptor가 회신된다. descriptor 란 Protocol Buffers의 심볼을 인코딩, 디코딩하기 위한 메타데이터의 집합니다.파일 디스크립터는 그 이름대로 Protocol Buffers 의 정의가 적혀있는 파일에 대한 디스크립터다. 이 샘플의 경우는 helloworld.proto 파일이다. 


```sh
host (TYPE_STRING) =>
v file_containing_symbol
file_containing_symbol (TYPE_STRING) => helloworld.Greeter
host (TYPE_STRING) => {
  "file_descriptor_response": {
    "file_descriptor_proto": [
      "ChBoZWxsb3dvcmxkLnByb3RvEgpoZWxsb3dvcmxkIhwKDEhlbGxvUmVxdWVzdBIMCgRuYW1lGAEgASgJIh0KCkhlbGxvUmVwbHkSDwoHbWVzc2FnZRgBIAEoCTJJCgdHcmVldGVyEj4KCFNheUhlbGxvEhguaGVsbG93b3JsZC5IZWxsb1JlcXVlc3QaFi5oZWxsb3dvcmxkLkhlbGxvUmVwbHkiAEI2Chtpby5ncnBjLmV4YW1wbGVzLmhlbGxvd29ybGRCD0hlbGxvV29ybGRQcm90b1ABogIDSExXYgZwcm90bzM="
    ]
  }
}
```

base64을 디코딩해본다. Base64인코딩된 문자열은 다음 Go 프로그램으로 파싱할 수 있다. (고 한다.)

```go
package main

import (
    "encoding/base64"
    "fmt"
    "log"

    "github.com/golang/protobuf/protoc-gen-go/descriptor"
    "google.golang.org/protobuf/proto"
)

func main() {
    var out []byte
    in := "ChBoZWxsb3dvcmxkLnByb3RvEgpoZWxsb3dvcmxkIhwKDEhlbGxvUmVxdWVzdBIMCgRuYW1lGAEgASgJIh0KCkhlbGxvUmVwbHkSDwoHbWVzc2FnZRgBIAEoCTJJCgdHcmVldGVyEj4KCFNheUhlbGxvEhguaGVsbG93b3JsZC5IZWxsb1JlcXVlc3QaFi5oZWxsb3dvcmxkLkhlbGxvUmVwbHkiAEI2Chtpby5ncnBjLmV4YW1wbGVzLmhlbGxvd29ybGRCD0hlbGxvV29ybGRQcm90b1ABogIDSExXYgZwcm90bzM="
    out, err := base64.StdEncoding.DecodeString(in)
    if err != nil {
        log.Fatal(err)
    }

    var m descriptor.FileDescriptorProto
    if err := proto.Unmarshal(out, &m); err != nil {
        log.Fatal(err)
    }

    fmt.Println(*m.Name) // examples/helloworld/helloworld/helloworld.proto
    fmt.Println(*m.Service[0].Name) // Greeter
    fmt.Println(*m.Service[0].Method[0].Name) // SayHello
}
```

실행해보려고 했지만 이 두 라인에서 참조에러가 발생했다. 

```go
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"google.golang.org/protobuf/proto"
)
```

음.. 

```sh
go run .\go-reflection-parse.go
go-reflection-parse.go:8:2: no required module provides package github.com/golang/protobuf/protoc-gen-go/descriptor: go.mod file not found in current directory or any parent directory; see 'go help modules'
go-reflection-parse.go:9:2: no required module provides package google.golang.org/protobuf/proto: go.mod file not found in current directory or any parent directory; see 'go help modules'
```

다음 두 명령을 실행해서 모듈을 인스톨한 후에도 결과는 동일했다. 막혔다..😓

```sh
$ go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
```

Go 기초(특히 모듈이나 패키지 관리 부분)부터 정리하는게 좋겠다. 


일단 그냥 base64 디코딩해서보면 다음과 같은 형태다. 

![](/images/grpc-reflection-1.png)


Go Modules를 개념정리한 후 프로젝트 폴더로 이동 후 다음 명령어를 실행했다. 그러자 에러가 없어졌다!! 🧁

```sh
go mod init grpc-test
go get google.golang.org/protobuf
go get github.com/golang/protobuf
```

실행결과는 다음과 같다. 파싱에 성공하여 proto 파일명과 서비스명 메서드명을 추출하는데 성공하였다. 

```sh
PS D:\projects\go-sample-grpc> go run .\go-reflection-parse.go
helloworld.proto
Greeter
SayHello
```


# 참고
- https://syfm.hatenablog.com/entry/2020/06/23/235952  <-- Evans를 작성한 사람의 블로그 글이다. 자세하게 설명해주고 있어서 도움이 된다. 
- https://grpc.io/docs/guides/reflection/
- https://github.com/grpc/grpc/blob/master/doc/server-reflection.md