---
layout: post
title: "Protocol Buffer 정리"
categories: [프로그래밍]
tags: [프로그래밍, 프로토콜버퍼, protocol buffer]
toc: true
---

# 개요
- 구글이 개발한 데이터 구조화 방식이다. 
- gRPC 등의 프로토콜에서도 프로토콜 버퍼를 사용하므로 알아두면 좋다. 
- [공식 사이트는 여기](https://developers.google.com/protocol-buffers){:target="_blank"}

# 사용이 필요한 곳
- 서로 다른 언어로 개발된 프로그램들 사이에서의 통신을 위해서 사용한다고 알고 있다. 
- 예를 들면 Java로 개발된 프로그램과 Python으로 개발된 프로그램이 서로 통신하고 싶을 때 사용할 수 있다. 
- 두 프로그램이 이해할 수 있는 공통 스펙으로 프로토콜 버퍼를 사용하는 것이다. 

# 흐름 
- 프로토콜 버퍼는 proto file 을 컴파일해주는 컴파일러 (protoc) 와 각 프로그래밍 언어에서 프로토콜 버퍼를 사용하개 해주는 라이브러리 SDK로 구성되어 있다. 
- 메세지의 스펙을 proto file (확장자가 .proto 인 파일) 에 기술한다. 
- 그리고 proto file 을 각 언어에서 인식가능한 파일로 컴파일한 후, 각 프로그래밍 언어에서는 SDK를 통해 사용하는 흐름이다. 

# 컴파일러 설치 
- [이 곳](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation){:target="_blank"} 을 참고하였다. 
- c++ 유저가 아니면 미리 컴파일된 바이너리를 다운로드 받는 것을 추천한다고 한다. 
- 일단 파이썬 SDK를 사용해서 테스트해보려고 한다. 