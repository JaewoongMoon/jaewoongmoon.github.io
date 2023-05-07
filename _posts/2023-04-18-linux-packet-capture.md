---
layout: post
title: "리눅스 패킷 캡처하기"
categories: [리눅스, 네트워크, 패킷캡처]
tags: [리눅스, 네트워크, 패킷캡처]
toc: true
---

# 개요
- 리눅스에서 패킷캡처하는 방법을 정리한다. 
- 리눅스 서버로 들어오는 통신 내용을 직접 체크하고 싶을 때 사용한다. 
- 예를들면 어떤 스캐너의 페이로드가 중간에 변조되지 않고 제대로 타겟 서버에 전달되었는지 등을 체크하고 싶을 때 사용한다. 

# 기본적인 흐름
- 리눅스 서버에서 `tcpdump`를 사용해서 패킷을 캡처한다. pcap확장자 파일로 저장한다. 
- pcap파일을 다운로드한다. 
- 로컬 PC에서 와이어샤크를 이용해서 pcap파일을 분석한다. 


# tcpdump 설치
리눅스에서 제공하는 기본 패키지 매니저로 설치할 수 있다. 

```sh
sudo yum install tcpdump
```

설치가 완료되었으면 실행가능한지 확인해본다. 

```sh
$ tcpdump -h
tcpdump version 4.9.2
libpcap version 1.5.3
OpenSSL 1.0.2k-fips  26 Jan 2017
Usage: tcpdump [-aAbdDefhHIJKlLnNOpqStuUvxX#] [ -B size ] [ -c count ]
                [ -C file_size ] [ -E algo:secret ] [ -F file ] [ -G seconds ]
                [ -i interface ] [ -j tstamptype ] [ -M secret ] [ --number ]
                [ -Q|-P in|out|inout ]
                [ -r file ] [ -s snaplen ] [ --time-stamp-precision precision ]
                [ --immediate-mode ] [ -T type ] [ --version ] [ -V file ]
                [ -w file ] [ -W filecount ] [ -y datalinktype ] [ -z postrotate-command ]
                [ -Z user ] [ expression ]

```

# tcpdump 실행하기
- 툴실행에는 루트권한이 필요하다. 

```sh
sudo su
```

## 실시간 80포트 캡쳐하기 
- 80포트를 캡쳐하는 샘플 커맨드이다. 

```sh
tcpdump -nnSX port 80
```

## 80포트 캡쳐 저장하기 
다음 명령을 실행하면 캡처가 시작된다. 캡처를 종료하고 싶으면 Ctrl+C로 중지한다. pcap형식의 파일이 저장된다. 

```sh
tcpdump port 80 -w capture_file
```



# 참고 
- https://danielmiessler.com/study/tcpdump/