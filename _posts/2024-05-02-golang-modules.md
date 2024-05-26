---
layout: post
title: "Golang Modules 정리"
categories: [프로그래밍]
tags: [프로그래밍, Golang]
toc: true
---

# 개요
Go에서 생소하게 느껴지는 모듈관리에 대해 정리해둔다. 

# Go Modules 개요
- Go Modules는 Go 프로젝트 내에서 의존성(dependency)을 관리해준다. 
- Go Modules는 2018년 8월에 발표된 1.11 버전부터 사용가능하다. 1.13 버전에서는 기본값이 되었다.
- 그 이전의 Go 프로젝트에서는 GOPATH에 기반한 개발을 했다. 즉, 모든 코드가 단일 작업 공간에 저장되는 것이다. 
- Go 모듈을 사용하면 GOPATH 외부에서 코드를 구성할 수 있다. (파이썬의 virtualenv를 사용한 개발와 비슷한 개념으로 보인다. 각 프로젝트별로 의존성을 별도로 관리하는 것이다.)

# 한번 사용해 보자. 

## 의존성 관리 파일 생성
대충 go 프로젝트 폴더를 하나 만들고 거기서 커맨드를 실행해보자. 

```sh
go mod init <module-name>
```

다음과 같이 실행했다. 

```sh
PS D:\tutorials\go\go-modules-test> go mod init moon-test
go: creating new go.mod: module moon-test
PS D:\tutorials\go\go-modules-test>
```

만들어진 go.mod 의 내용은 다음과 같다. 

```
module moon-test

go 1.20

```

## 라이브러리 사용하기 
예를 들어, 값의 동일성을 비교해주는 라이브러리 [cmp](https://pkg.go.dev/github.com/google/go-cmp/cmp)를 추가해보자. 

프로젝트에서 다음과 같이 실행한다. 

```sh
go get github.com/google/go-cmp
```

```sh
PS D:\tutorials\go\go-modules-test> go get github.com/google/go-cmp
go: added github.com/google/go-cmp v0.6.0
PS D:\tutorials\go\go-modules-test>
```

실행 후의 go.mod파일은 다음과 같이 변경된다. 라이브러리의 버전이 명시되어 있는 것을 알 수 있다. 

```
module moon-test

go 1.20

require github.com/google/go-cmp v0.6.0 // indirect

```

## 라이브러리 업데이트하기 
라이브러리를 업데이트하는 것은 보안상 중요하다. 다음 커맨드를 사용하면 호환되는 적절한(compatible) 최신 버전으로 업데이트해준다. 

```sh
go get -u
```


# 참고 
- https://medium.com/google-developer-indonesia/understanding-go-modules-a-comprehensive-guide-119638ed7e45#:~:text=What%20are%20Go%20Modules%3F,your%20code%20outside%20the%20GOPATH.