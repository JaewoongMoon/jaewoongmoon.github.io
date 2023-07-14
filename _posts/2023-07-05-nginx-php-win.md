---
layout: post
title: "Windows 환경에서 nginx와 php연동하기 "
categories: [환경구축, nginx, php]
tags: [환경구축, nginx, php]
toc: true
---

# 배경
- 웹 취약점 테스트를 위해 로컬PC환경에서 간단하게 수정 및 실행이 가능한 서버가 필요했다. 
- HTML뿐이면 Node.js의 http-server모듈이 가장 간단하지만 이 걸로는 .php, .jsp와 같은 서버측 페이지를 개발할 수 없기 때문에 한계가 있었다. 
- 빠르게 테스트하기 위해서는 역시 php가 간단하고, 이를 위해서 Windows PC에 nginx와 php를 설치하기로 결정했다. 

# Nginx 
## 설치
https://nginx.org/en/docs/windows.html 에서 Windows용 nginx를 다운로드한다. zip파일이 다운로드 된다. 적당한 위치에 zip파일을 푼다. 나는 `C:\nginx\nginx-1.25.1` 에 풀었다. 

## 커맨드
```sh
cd C:\nginx\nginx-1.25.1
start nginx # 기동
.\nginx.exe -s reload #재구동
.\nginx.exe -s quit # 종료
```

## 루트 디렉토리 변경
`conf/nginx.conf` 파일에서 server부분에서 `root html;` 로 되어있는 부분을 내가 테스트하고 싶은 프로젝트의 경로로 변경했다. 매뉴얼을 보니 nginx는 Unix식 경로만 인식가능한 것 같다. Windows경로인 역슬래시(\)는 인식하지 못하므로 Window경로에서 역슬래시부분을 슬래시(/)로 바꿔준다. 

# PHP 
이어서 PHP관련 부분을 설치&설정한다. 

## Nginx PHP모듈 설치 
https://windows.php.net/download/ 에서 다운로드받는다. 최신의 Thread Safe 버전을 받았다. `php-8.2.7-Win32-vs16-x64.zip`

적당한 곳에 zip파일을 푼다. 나는 `C:\php\php-8.2.7-Win32-vs16-x64` 에 풀었다. 푼곳에 `php-cgi.exe`과 `php.exe`가 존재하는지 확인한다. 

## 커맨드 
```sh
cd C:\php\php-8.2.7-Win32-vs16-x64
.\php-cgi.exe -b 127.0.0.1:9123
```

## nginx에서 PHP설정 추가
`conf/nginx.conf`파일에 PHP설정을 추가(주석처리 되어있는 부분을 제거)한다. 

```
location ~ \.php$ {
    root           html;
    fastcgi_pass   127.0.0.1:9123;
    fastcgi_index  index.php;
    fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
    include        fastcgi_params;
}
```

설정후에 nginx를 재구동한다. 

```sh
cd C:\nginx\nginx-1.25.1
.\nginx.exe -s reload 
```

## PHP동작테스트
DocumentRoot 경로에 index.php추가해서 잘 동작하는지 확인한다. 

index.php
```php
<?php phpinfo(); ?>
```

http://localhost/index.php 로 접속했을 때 phpinfo 페이지가 잘 나온다면 성공이다. 

# 참고 
- https://qiita.com/Yuhkih/items/2b26f3761578637d0005
- https://www.nginx.com/resources/wiki/start/topics/examples/phpfastcgionwindows/