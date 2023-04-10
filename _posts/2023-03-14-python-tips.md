---
layout: post
title: "파이썬 자잘한 팁 정리"
categories: [프로그래밍, 파이썬]
tags: [프로그래밍, 파이썬]
toc: true
---

# 개요 
자주 쓰이는 자잘한 파이썬 코드를 정리해둔다. 


# 경로관련
## 실행되는 메인 파일 기준으로 경로를 얻고 싶을 때
- 다음 코드를 사용한다.  
- 예를들면 main.py 파일로 실행할 경우 해당 파일의 경로가 리턴된다. 


```py
import os
dir_name = os.getcwd()
```

## 특정 파일에서 자신의 경로를 얻어오고 싶을 떄
- 예를들어 특정 패키지(디렉토리)의 어떤 파일이 자신의 경로를 기준으로 파일에 접근하고 싶을 때 사용한다. 

```py
import os
dir_name = os.path.dirname(__file__)
```


# 날짜 관련
## 리눅스 에포크 타임을 날짜로 변환하고 싶을 때 
- 로컬 시간(프로그램이 실행되는 머신이 위치하고 있는 시간대)으로 변환하고 싶으면 datetime의 `fromtimestamp`메서드를 사용한다. 
- 주의점: `fromtimestamp`는 리눅스 서버의 date설정을 따라간다. 즉, 리눅스 서버의 시간이 UTC로 설정되어 있으면 UTC시간으로 출력된다. 

이 시간을 변경하고 싶으면 다음 명령어를 참고한다. 

```sh
sudo cat /etc/localtime
sudo rm /etc/localtime
sudo ln -s /usr/share/zoneinfo/Asia/Seoul /etc/localtime
```

- UTC시간으로 변경하고 싶다면 `utcfromtimestamp`메서드를 사용한다. 
- 사용예는 다음과 같다. 

```py
def parse_unix_time(ts):
    local_datetime = datetime.fromtimestamp(ts)
    local_timestamp = local_datetime.strftime("%Y-%m-%d %H:%M:%S")
    print(local_timestamp)
```
