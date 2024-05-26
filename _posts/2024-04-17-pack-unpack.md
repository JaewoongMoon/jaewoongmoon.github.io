---
layout: post
title: "파이썬 패킹 및 언패킹 개념 정리"
categories: [프로그래밍, 파이썬]
tags: [프로그래밍, 파이썬]
toc: true
---


# 개요
- 파이썬에는 패킹과 언패킹을 담당하는 struct 모듈이 있다. 
- 이 모듈은 Python과 C 구조체 사이의 값을 변환해준다. 
- 네트워크 해킹을 하다보면 자주 마주치게 된다. 
- 이 기회에 패킹과 언패킹 개념에 대해 정리해둔다. 

# 개념
## 패킹/언패킹 필요성
- 네트워크 상에서 데이터를 빠르게 주고 받기 위해서는 데이터를 텍스트 기반이 아닌, 바이너리데이터로 만들어서 주고 받을 필요가 있다. 

## 패킹 
- 패킹은 특정 값을 바이너리 데이터(bytes) 바꾸는 것이다. 
- 네트워크 공간으로 여행을 떠나기 위해 캐리어에 짐을 빈틈없이 넣는(패킹하는) 이미지를 연상해보자. 

## 바이트오더
- 바이트오더란 바이트를 어떤 순서로 정렬했는지를 의미한다. 리틀 엔디안인지 빅 엔디안인지 등을 말하는 것이다.
- 파이썬에서는 포맷문자열에 사용하는 문자 `@, =, <, >, !`가 바이트오더를 의미한다. 다음과 같다. 
- `@`와 `=`는 native를, `<`는 리틀엔디안을, `>`와 `!`는 빅엔디안을 의미한다. 
- 네트워크상에서 주고 받을 때는 빅엔디안이 기본이므로 바이트오더는 `>`를 사용할 때가 많을 것 같다. 기억해두자. 

![](/images/python-pack-byte-order.png)
*출처:https://docs.python.org/3/library/struct.html*

## 포맷문자열
- 바이너리 데이터가 어떤 포맷으로 패킹된 것인지 알려주는 역할을 한다. 
- 포맷문자열의 제일처음에는 바이트오더를 적고, 다음에 이어서 문자포맷을 적어준다. 
- 예를 들면 `>H`와 같은 식이다.
- 문자 포맷은 데이터의 타입별로 미리 정해진 것이 있다. 
- [여기](https://docs.python.org/3/library/struct.html)에서 볼 수 있다. 
- 예를들어 문자(포맷)`H`는 `unsigned short`타입을 의미한다. 

[]![](/images/python-pack-format-string-table.png)
*출처:https://docs.python.org/3/library/struct.html*

- **패킹할 때와 언패킹할 때 포맷문자열은 동일한 문자열이 들어가야 한다!**


## 언패킹
- 언패킹은 패킹의 반대 과정이다. 바이트배열을 원래의 값으로 변환한다. 

# 파이썬 예제
패킹/언패킹에 대해 대략 이해했으면 실제 코드를 살펴보자. 

## struct 모듈 
- 파이썬에서 패킹과 언패킹은 struct 모듈을 사용하면 가능하다.  
- struct모듈은 파이썬 3에서부터 사용가능하다. 

## pack 함수 

pack함수로 패킹을 실시한다. pack함수는 다음과 같은 문법으로 사용한다. 
- 첫번째 인자는 포맷 문자열이다. 
- 두번째부터의 인자는 패킹할 데이터이다. 하나만 넘겨도 되고, 여러 개를 넘겨줘도 된다. 
- 포맷문자열의 길이는 인수의 개수에 맞게 지정한다. 예를 들어 두개의 캐릭터 변수를 인수로 넘겨준다면 포맷스트링은 `cc`를 지정해준다. 네개라면 `cccc`다. 

```py
struct.pack(format, v1, v2, …)
```

## calcsize 함수
- 포맷 문자열을 넘겨주면 몇 바이트의 바이너리 데이터로 패킹되는지 알려주는 함수다. 


## 샘플코드
- 포맷 문자열 `>bhl`는 빅엔디언, signed char(1바이트), short(2바이트), long(4바이트)를 의미한다. 
- 결과를 보면, 1이 `\x01`로, 2가 `\x00\x02`로, 3이 `\x00\x00\x00\x03`으로 패킹된 것을 알 수 있다. 

```py
>>> import struct
>>> struct.pack(">bhl", 1, 2, 3)
b'\x01\x00\x02\x00\x00\x00\x03'
>>> struct.unpack(">bhl", b'\x01\x00\x02\x00\x00\x00\x03')
(1, 2, 3)
>>> struct.calcsize(">bhl")
7
>>>
```


# 참고
- https://wikidocs.net/104663
- https://www.geeksforgeeks.org/struct-module-python/
- https://docs.python.org/3/library/struct.html
- https://salguworld.tistory.com/362
- https://www.educative.io/answers/what-is-the-python-struct-module
- https://coding-yoon.tistory.com/171