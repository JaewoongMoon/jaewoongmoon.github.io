---
layout: post
title: "Eclipse에서 톰캣 빌드 및 구동환경 구축"
categories: [톰캣, Eclipse]
tags: [톰캣, Eclipse]
toc: true
last_modified_at: 2024-02-09 21:00:00 +0900
---

# 개요
- 톰캣을 빌드할 수 있는 환경을 구축하는 방법을 정리해둔다. 
- 톰캣의 소스코드를 분석하거나 변경하면서 동작을 확인해본더가 할 때 활용할 수 있다.

# 환경
1. Windows 10 
2. Eclipse 2023-12 EE 버전

# 사전작업: 빌드에 필요한 툴 설치 
## Java (JDK)
- ~~버전 몇 이상인지는 나와있지 않지만 자바는 하위호환을 잘 지원하기 때문에 최신 버전을 사용하면 문제없을 것이다.~~ 아니다. 문제있다. 특정 버전을 사용해야 한다. 
- 2024/01/31 기준 main 브랜치는 최신버전인 OpenJDK 21버전으로 빌드에 성공한다. 
- 빌드에 필요한 자바 버전은 `build.xml` 파일을 보면 나와있다. 
- 8.5.x 라면 빌드하는데 자바11이 필요하다. (최신 버전이면 빌드에 실패한다.) 

```xml
  <!-- Java EE 7 platform requires Java 7+ -->
  <!-- Keep in sync with webapps/docs/tomcat-docs.xsl -->
  <property name="compile.release" value="7"/>
  <property name="min.java.version" value="7"/>
  <property name="build.java.version" value="11"/>
```

- [여기](https://jdk.java.net/archive/)에서 OpenJDK를 다운로드할 수 있다. 
- 참고로 더 오래된 OpenJDK 7은 [여기](https://github.com/alexkasko/openjdk-unofficial-builds#openjdk-unofficial-installers-for-windows-linux-and-mac-os-x)에서 다운로드 가능하다. 
- 다운로드받은 zip파일의 압축을 적절한 위치에 푼다. 해당 위치를 `JAVA_HOME` 환경 변수에 등록한다. (기존에 등록된 값을 덮어쓰기 한다.)


## Ant 
빌드에는 Ant가 필요한다. ant를 설치해둔다. 
- [여기](https://ant.apache.org/bindownload.cgi)에서 다운로드 가능하다. 1.10.14 버전을 설치했다. 
- zip 파일을 다운로드해서 압축을 푼후 /bin 폴더를 PATH에 등록해둔다.


# 소스코드
- [여기](https://github.com/apache/tomcat/tree/8.5.x)에서 소스 코드를 볼 수 있다. 
- 검증 대상은 8.5.x 브랜치다.

소스코드를 github에서 clone해둔다. 

```sh
git clone https://github.com/apache/tomcat.git
```

## 특정 버전 코드로 스위칭하기 

```sh
## 리모트 브랜치 상황 보기
> git remote show origin
# 8.5.x 브랜치로 스위칭
> git checkout 8.5.x
Updating files: 100% (3123/3123), done.
Switched to a new branch '8.5.x'
Branch '8.5.x' set up to track remote branch '8.5.x' from 'origin'.
```


[!] 톰캣 경로를 `tomcat` 에서 `tomcat-8.5.x`로 변경한다. 나중에 이클립스 빌드에서 오류나지 않게 하기 위해서 필요하다. 


# 빌드
## 빌드 커맨드 
다음 명령어로 빌드한다. 

```sh
cd tomcat-8.5.x 
ant 
# 프록시 서버를 통해야 한다면 
ant -autoproxy
```

- 만약 Java버전이 맞지 않으면 빌드 실패가 발생하면서 어떤 버전이 필요한지 알려준다. 

## 빌드 결과 
빌드에 성공하면 다음 두 폴더가 생성된다. 

1. output
- 프로젝트 루트에 생성된다. 
- /output/build 폴더에 톰캣 빌드 결과물이 생성된다. 

2. tomcat-build-libs
- 빌드에 필요한 라이브러리가 `${user.home}/tomcat-build-libs`에 설치된다. (프로젝트 루트의 바깥이다.) 
- 변경하고 싶다면 `${tomcat.source}/build.properties` 파일을 수정하면 된다. 이 파일은 디폴트로는 존재하지 않는다. `build.properties.default` 파일이 존재하고 있으므로 이 파일을 복사해서 만들면 된다. 


# 이클립스에서 톰캣 구동하기 
이어서 이클립스에서 톰캣을 구동하는 방법을 정리한다. 

## 이클립스용 프로젝트 파일 빌드 
먼저 이클립스 프로젝트로 임포트해야 한다. 이를 위해서 ant에 target-name을 `ide-eclipse` 로 주어서 이클립트 프로젝트 파일을 만든다. 

1. `build.properties.default` 파일을 복사해서 `build.properties`를 만든다. (이 단계는 꼭 필요하지 않을 수도 있다.)

2. 다음 명령어를 실행한다. 

```sh
cd tomcat-8.5.x 
ant ide-eclipse -autoproxy
```

실행하면, `.settings`폴더, `.classpath`, `.project` 등 이클립스 프로젝트에 필요한 파일이 생성된다. 

## 프로젝트 임포트
이클립스에서 File > Import > Existing Projects into Workspace 를 선택해서 임포트 할 수 있다. 

![](/images/eclipse-tomcat-project-import.png)

## 톰캣 실행 포트 변경하기
- 톰캣은 실행시 8005포트, 8080포트, 8009포트를 오픈한다. 이중에 사용중인 포트가 있다면 실행이 중지된다. 
- 💢Windows 10에서는 왜인지 8005포트를 시스템 프로세스가 사용하고 있다. 이 것을 바꾸는 것은 어려워보인다. 톰캣의 8005포트를 변경하는게 나아보인다. 
- `/conf/server.xml`을 보면 `<Server port="8005" shutdown="SHUTDOWN">` 코드가 있다. 여기를 8006으로 변경하고 다시 빌드한다. (ant -autoproxy실행) 

## 이클립스에 실행옵션 추가하기 
톰캣을 구동하거나 종료하는 Run설정을 Run설정에 추가하는 과정이다. 

`/res/ide-support/eclipse` 폴더에 존재하는 `start-tomcat.launch` 과 `stop-tomcat.launch` 를 이클립스에서 선택한 후 마우스 오른쪽 버튼, Run as 를 선택해서 실행할 수 있다. 

![](/images/eclipse-start-tomcat-run-as.png)

참고로 start-tomcat.launch 파일을 보면 `tomcat-8.5.x`와 같이 경로가 들어가 있는 것을 볼 수 있다. 

```xml
<stringAttribute key="org.eclipse.jdt.launching.VM_ARGUMENTS" value="-Dcatalina.home=${project_loc:/tomcat-8.5.x/java/org/apache/catalina/startup/Bootstrap.java}/output/build"/>
```

## 이클립스 프로젝트가 Ant를 인식하도록 하기 
내일 조사하자. 

## 이클립스에서 별도로 빌드를 구축하는 방법
아래에 정리한 것은 어거지로 되도록 만드는 방법이다. (Ant빌드와 이클립스 빌드가 따로 논다. Ant가 빌드한 것은 /output에 저장되지만 이클립스가 빌드한 것은 /.settings/output에 저장된다.) 이클립스에서 제대로 Ant를 인식시케는 방법이 확립되면 이 글에서 삭제할 예정이다.

### Java 컴파일러 버전 설정
- 이클립스는 Ant가 빌드한 것을 인식하지 못하는 것 같다. 
- 프로젝트 설정(Property)에서 컴파일러 버전을 버전11로 설정해준다. 

![](/images/eclipse-tomcat-jdk-11-setting.png)

### Java Build Path 설정
프로젝트 설정(Property)에서 Java Build Path를 별도로 설정해주어야 한다. 

1. Source 탭에서는 기본적으로 output 폴더가 포함되어 있다. 이 부분은 삭제해준다. 

![](/images/eclipse-tomcat-build-path-source.png)

2. Library 탭에서는 빌드에 필요한 외부 파일을 지정해줄 필요가 있다. 
- ant 빌드후에 생긴 `tomcat-build-libs` 폴더에 있는 모든 jar 파일과 ant 설치 폴더에 있는 `ant.jar` 파일을 build path에 지정해주어야 한다. 
- Add External JARs... 를 선택해서 일일히 추가해주었다. (뭔가 더 스마트한 방법이 있을 것 같다.)

참고로 빌드 패스가 제대로 설정되지 않을 상태로 구동후에 http://localhost:8080에 접속하면 다음과 같은 에러가 발생한다. 

![톰캣 접근 에러](/images/tomcat-eclipse-error-1.png)


### 번외: Eclipse에서 Ant를 쓰는 경우 Java Build Path 설정은 어떻게 되는가?
샘플을 하나 만들어보자. [여기](https://waspro.tistory.com/237)를 보고 만들어본 바, Java Build Path는 동일했다. 프로젝트에서 Ant를 쓴다고 바뀌는 것이 아닌 것 같다. 

### 이클립스 빌드 결과 파일의 위치를 조정
- 이클립스가 빌드한 결과는 디폴트로 `\.settings\output`에 저장되도록 되어 있다. 
- 여기서 문제가 있는데 모든 소스코드가 동일한 패키지를 기준으로 빌드된다는 점이다. 
- 예를 들어 ant 설정파일 build.xml 내에는 webapps 폴더의 빌드 결과는 /output/build/webapps 에 저장되도록 하고 있다. (이래야 제대로 동작한다.) 
- 그러나 이클립스의 Java Build Path 설정으로는 빌드 결과를 한곳에 때려넣는 식으로 밖에 할 수 없다. 
- 그 결과 `/webapps/examples/WEB-INF/classes/` 를 빌드하면 `/output/build/webapps/examples/WEB-INF/classes/`에 저장되는 게 아니라 `/.settings/output/` 에 저장된다. 
- 그 결과 톰캣에서 이 부분을 구동하려고 하면 클래스를 찾을 수 없는데요? 오류가 난다... 😑
- 여기를 매끄럽게 연동되도록 하는 것은 찾아보면 방법이 있을 것 같으나 지금은 그냥 넘어가자. 필요하면 Ant에서 빌드한 파일을 복붙하면 해결된다. 


### 톰캣 구동 테스트 
run > start-tomcat을 선택해서 톰캣을 구동해본다.  문제없이 구동되었다면 웹 브라우저로 접근해본다. 다음과 같이 나온다면 성공이다. 

![톰캣 구동 성공](/images/tomcat-eclipse-success.png)


# 참고 
- https://github.com/apache/tomcat
- https://cwiki.apache.org/confluence/display/TOMCAT/Developing
- https://tomcat.apache.org/tomcat-8.5-doc/building.html#Building_with_Eclipse