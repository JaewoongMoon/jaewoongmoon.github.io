---
layout: post
title: "Metasploit 개발 환경 구축하기"
categories: [보안, 취약점스캐너]
tags: [취약점, 스캐너, metasploit, 개발환경 구축]
toc: true
last_modified_at: 2023-08-15 15:02:00 +0900
---

# 개요
- Metasploit 에서 exploit 소스 코드를 분석 또는 개발하기 위한 환경을 구축하는 방법을 정리해둔다. 
- Metasploit은 거의 Ruby로 개발되어 있다. 따라서 Metasploit 개발환경을 구축하는 것은 Ruby 개발환경을 구축하는 것과 거의 동일하다. 
- 소스코드 에디터는 Visual Studio Code 를 사용한다. 

# 소스코드 clone

```sh
git clone https://github.com/rapid7/metasploit-framework.git
```

# Ruby 설치
Ruby개발을 위해서는 당연히 Ruby 를 설치해야 한다. 

https://rubyinstaller.org/downloads/ 에서 OS에 맞는 것을 다운로드 받아서 설치한다. 

# Visual Studio Code 
https://code.visualstudio.com/download 에서 다운로드 받아서 설치한다. 


## Ruby 개발용 Visual Studio Code 확장 프로그램 설치 
1. 설정 > Extensions 으로 들어간다. 
2. 검색어에 Ruby를 친다. 
3. 요녀석을 설치해준다. 

![ruby 확장프로그램](/images/vscode-ruby-extension.png)

## 코드 점프 설정
코드 점프(code jump)란 소스 코드 분석시에 해당 함수의 정의로 이동하는 기능이다. 코드 분석시에는 필수 기능이다. VsCode의 디폴트 설정에서는 이 것이 off로 되어있다고 한다. 

1. 설정 > Settings로 들어간다. 
2. 검색어에 ruby 라고 친다.
3. Intellisense를 false에서 rubyLocate로 변경한다. 

![Intellisense변경](/images/vscode-ruby-extension-intell.png)

4. VSCode를 재부팅한다. 

## 코드 점프 테스트 
함수의 정의가 보고 싶은 부분을 Ctrl키를 누른상태에서 마우스로 클릭한다. 
스크린샷은 modules/exploits/windows/msb/ms08_067_netapi.rb 파일의 일부분이다. 

![함수 정의로 이동](/images/vscode-ruby-code-jump-1.png)


함수 정의로 이동된다! 이 함수는 lib/msf/core/exploit/remote/smb/client.rb 파일에 정의되어 있었다. 

![함수 정의로 이동 완료](/images/vscode-ruby-code-jump-2.png)

코드 점프가 잘 되는 것을 확인했다. 일단 소스 코드 분석을 위한 최소한의 준비는 완료되었다. 

# 디버깅 하기 
- 어떤 exploit 코드를 분석할 때 디버깅을 할 수 있으면 매우 좋다. 
- 예를 들면, 어떤 함수의 리턴 값이나 함수 내부에서 중간 값 등을 확인해볼 수 있으므로 매우 유용하다. 
- 계속 정리해나가자. 

# 참고
- https://www.fuwamaki.com/article/404
- https://www.rapid7.com/blog/post/2014/03/14/debugging-metasploit-modules-with-pry-debugger/
- https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html