---
layout: post
title: "파이썬에서 리눅스 명령어 호출하기"
categories: [프로그래밍, 파이썬]
tags: [프로그래밍, 파이썬, 리눅스 프로그램 연동]
toc: true
---

# 개요
- 파이썬에서 리눅스 프로그램을 연동하고 싶을 때가 있다. 
- 예를들어, curl 프로그램을 여러번 시도하고 싶을 때 컨트롤 부분은 파이썬으로 작성하고 HTTP 요청은 curl로 처리하는 등이다. 
- 이럴 때, 파이썬의 `subprocess` 모듈을 사용한다. 

# subprocess 모듈
서브프로세스를 호출할 때 추천하는 방법은 run 함수를 사용하는 것이라고 한다. 
```
The recommended approach to invoking subprocesses is to use the run() function for all use cases it can handle. For more advanced use cases, the underlying Popen interface can be used directly.
```

## subprocess.run 함수 
기본적으로 서브프로세스가 끝날 때가지 기다리는 것 같다. 
```
Run the command described by args. Wait for command to complete, then return a CompletedProcess instance.
```

## subprocess.Popen 함수
다음과 같이 사용하는 패턴이 많다. 

```py
from subprocess import Popen, PIPE
cmd = "curl " # 리눅스 커맨드 
p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
outs, errs = p.communicate()
print(outs)
print(errs)
```

파라메터의 사양을 잘 이해해두는 게 중요할 것 같다. 목적에 따라 어떻게 파라메터를 지정해야하는지가 달라지기 때문이다. 예를들어, 리눅스 커맨드 실행이 종료될 때까지 파이썬 프로그램측이 기다리고 싶은지, 아니면 커맨드 실행 요청을 보내고 바로 다음 파이썬 코드를 실행하고 싶은지 등에 따라 달라질 수 있겠다. 

### 파라메터 분석
함수에 전달하는 `shell`, `stdout`, `stderr`은 무엇을 의미하는 것일까? 


#### shell
- 기본값은 False 이다. 
- 아래 공식 사이트의 설명을 보면 True로 설정되면 시스템에서 사용하는 shell의 실행환경을 기반으로 커맨드를 수행하는 것 같다. 
- 셸파이프나 파일명 와일드카드, 환경 변수 확장 등 셸의 여러 기능을 사용하고 싶다면 True로 설정한다. 

```
If shell is True, the specified command will be executed through the shell. This can be useful if you are using Python primarily for the enhanced control flow it offers over most system shells and still want convenient access to other shell features such as shell pipes, filename wildcards, environment variable expansion, and expansion of ~ to a user’s home directory. 
```

#### stdout/stderr
- 서브 프로세스의 표준 출력, 표준 에러 출력을 연결하는 파일 디스크립터를 지정한다. 간단하게 말하자면, 리눅스 커맨드 실행결과를 파이썬에서 출력하고 싶으면 `subprocess.PIPE`를 stdout, stderr 파라메터의 입력값으로 전달하면 된다. 

### proc.communicate 함수
프로세스와 커뮤니케이션 하기 위한 함수인 듯 하다. 
```
Interact with process: Send data to stdin. Read data from stdout and stderr, until end-of-file is reached. Wait for process to terminate and set the returncode attribute. The optional input argument should be data to be sent to the child process, or None, if no data should be sent to the child. If streams were opened in text mode, input must be a string. Otherwise, it must be bytes.
```

### 리눅스 프로그램을 그냥 실행시키고 싶을 때(끝날 때까지 기다리고 싶지 않을 때)
다음과 같이 파라메터를 지정하면 된다고 한다. 

```py
proc = Popen([cmd_str], shell=True,
             stdin=None, stdout=None, stderr=None, close_fds=True)
``` 

# 참고 링크
- https://docs.python.org/3/library/subprocess.html
- https://stackoverflow.com/questions/3516007/run-process-and-dont-wait