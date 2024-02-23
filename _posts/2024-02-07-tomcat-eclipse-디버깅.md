---
layout: post
title: "Eclipse에서 톰캣 구동환경 구축"
categories: [톰캣, Eclipse]
tags: [톰캣, Eclipse]
toc: true
---

# 개요
- 톰캣을 동적으로 디버깅하는 환경을 구축하는 방법을 정리해둔다. 
- 이전에 정리했던 "Eclipse에서 빌드 및 구동하기"에서 한단계 더 나아간 방법이다. 
- 톰캣에서 특정 HTTP 요청이 어떻게 처리되는지 (처리 시점의 변수나 메모리 값 등) 알 수 있다. 
- 자연히 톰캣에 존재하는 취약점을 검증하는데도 매우 강력한 힘이 되어 줄 것이다. 

# 목표
브레이크 포인트를 걸어서 특정 HTTP 요청을 처리하는 시점에서 중지, 내용을 확인해본다. 

# 환경
1. Windows 10 
2. Eclipse 2023-12 EE 버전

# 상세 
## STEP 1. 디버그 모드로 톰캣을 구동하기
먼저 톰캣 서버를 디버그 모드로 구동할 필요가 있다. [여기](https://cwiki.apache.org/confluence/display/TOMCAT/Developing#Developing-Debugging)에 의하면, 톰캣 구동시에 `-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n` argument를 추가해주면 된다고 적혀있다. 이 설정을 추가하면 8000번 포트로 디버거 프로그램의 접속을 대기하게 된다. 

이클립스에서 Run > Run Configuration ... 메뉴로 들어가서 start-tomcat 설정을 선택한다. Arguments 탭에서 위의 argument를 추가해준다.

![톰캣을 디버그 모드로 구동하기](/images/tomcat-start-tomcat-with-jpda.png)

추가한 뒤에 서버를 구동하면 8080포트와 함께 8000포트도 열린 것을 확인할 수 있다. 톰캣 서버 준비가 완료됐다. 



## STEP 2. 브레이크 포인트 걸기
소스 코드 파일에 브레이크 포인트를 건다. 예를 들어 이클립스에서 샘플 서블릿 파일 `/webapps/examples/WEB-INF/classes/HelloWorldExample.java` 파일을 열어서 43번 라인 (`response.setContentType("text/html");`)에 브레이크 포인트를 건다. 라인 번호 왼쪽을 더블클릭하면 된다. 



## STEP 3. 디버그 프로그램을 구동
톰캣 서버의 디버그용 포트(8000번 포트)에 접속할 디버그 프로그램(클라이언트)을 구동해야 한다. 이 프로그램이 유저(이클립스)와 톰캣사이에서 각종 디버깅에 필요한 명령을 전달해줄 것이다. 브레이크 포인트가 걸린 부분에서 프로그램을 정지하고 그 때의 값을 확인하고 한 스텝진행하고 하는 명령들이다. 

프로그램을 세팅하기 위해서 Run > Debug Configuraiton ... 메뉴로 들어간다. Remote Java Application을 선택하고 새로운 디버그 설정을 하나 추가해준다. 대상 프로젝트를 선택하고, Host는 localhost로, 포트는 8000으로 입력해준다. 

![톰캣 디버그 설정 추가](/images/tomcat-debug-program.png)

그리고 우측 하단의 Debug버튼을 눌러주면 프로그램이 실행된다. Debug탭이 나타나고 디버그용 스레드가 생성되어 대기중인 것을 볼 수 있다. 

![디버그 프로그램 구동 확인](/images/tomcat-debug-run.png)

## STEP 4. 확인
웹 브라우저로 `http://localhost:8080/examples/servlets/servlet/HelloWorldExample`에 접근해서 브레이크 포인트를 찍은 서블릿 프로그램이 구동되도록 한다. 그러면 브레이크 포인트에서 프로그램이 멈추고 이 시점의 값들을 확인할 수 있다. 성공이다! 😀

![톰캣 디버그 결과](/images/tomcat-debug-test-result.png)


# 참고 링크
- https://cwiki.apache.org/confluence/display/TOMCAT/Developing#Developing-Debugging