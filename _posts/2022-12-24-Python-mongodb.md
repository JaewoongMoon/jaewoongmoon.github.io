---
layout: post
title: "Python Mongodb 사용법"
categories: [프로그래밍]
tags: [프로그래밍, Python, Mongodb]
toc: true
---



# 트러블슈팅
## pymongo.errors.CursorNotFound 에러가 발생할 때 
현상: 다음과 같은 에러가 발생한다.   

```
pymongo.errors.CursorNotFound: cursor id 7073505406508033101 not found, full error: {'ok': 0.0, 'errmsg': 'cursor id 7073505406508033101 not found', 'code': 43, 'codeName': 'CursorNotFound'}
```

- 스택오버플로 (https://stackoverflow.com/questions/24199729/pymongo-errors-cursornotfound-cursor-id-not-valid-at-server) 를 읽어 보면, 10분이상 비활성(inactivate) 상태여서 타임아웃이 발생한 것이라고 한다. 
- 아마 처리가 10분이상 걸리는 작업이면 이 에러가 발생할 것 같기도 하다. 
- 몽고db의 collection 객체의 find 메서드 실행시에 `no_cursor_timeout=True` 옵션을 주면 해결된다고 한다. (대신, 반드시 처리가 끝나면 커서를 종료시켜야 한다.)
- 
