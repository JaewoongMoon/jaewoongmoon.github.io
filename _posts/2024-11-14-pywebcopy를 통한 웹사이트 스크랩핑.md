---
layout: post
title: "파이썬 pywebcopy 라이브러리로 이미지 파일 XMP 메타데이터 분석하기"
categories: [파이썬, 웹 크롤링]
tags: [파이썬, 웹 크롤링]
toc: true
last_modified_at: 2025-02-05 09:33:00 +0900
---

# 개요 
`pywebcopy` 라이브러리를 사용해서 웹 사이트를 로컬 PC에 저장(스크래핑)하는 방법을 정리한다. 

# 설치

```py
pip install pywebcopy
```

## lxml.html.clean 모듈 에러 

설치후에 사용하려고 하면 다음과 같은 에러가 발생할 수도 있다. 

```
ImportError: lxml.html.clean module is now a separate project lxml_html_clean.
```

다음 커맨드로 `lxml-html-clean` 라이브러리를 수동으로 설치해주면 해결된다. 

```py
pip install lxml-html-clean
```

# 사용방법

사용방법은 아주 간단하다. 

- 다음 코드를 참고한다. 
- TARGET_SITE_URL, LOCAL_SAVE_PATH, PROJECT_NAME 값을 적절히 바꿔준다. 
- 전체 웹 사이트를 저장하고 싶으면 save_website 함수를 사용한다. 
- 하나의 웹 페이지만 저장하고 싶으면 save_webpage 함수를 사용한다. 

※ 웹 사이트의 파일들은 {LOCAL_SAVE_PATH}/{PROJECT_NAME}/{DOMAIN} 에 저장된다. 

※ {PROJECT_NAME}의 값이 "/" 이면 제대로 동작하지 않는다. 

※ {PROJECT_NAME}의 값이 ""이면 URL의 값이 폴더명으로 들어간다. 예를들어 https://example.com을 스캔했다면 "https_example.com"과 같은 식으로 된다. 

```py
# -*- coding: utf_8 -*-
from pywebcopy import save_website, save_webpage
save_website(
      url="{TARGET_SITE_URL}",
      project_folder="{LOCAL_SAVE_PATH}",
      project_name="{PROJECT_NAME}",
      bypass_robots=True,
      debug=True,
      open_in_browser=False,
      delay=None,
      threaded=False,
)


```

# 주의점
회사 네트워크와 같이 프록시 서버가 전단에 있는 경우는 제대로 동작하지 않을 수 있다. 웹 사이트의 일부만 스크래핑되거나 한다. 프록시를 통하지 않는 환경에서 사용하는게 좋을 것 같다. 


# 에러
## pywebcopy.urls.LocationParseError 에러 
- LocationParseError에러는 사이트 크롤링중에 발견한 URL에 접근하려고 하는데, URL이 파싱불가능한 형태(잘못된 형태)일 때 발생한다. 
- 스크랩핑중 LocationParseError에러가 발생하면 작업전체가 멈추는 문제가 있다. 개선해줬으면 좋겠다. 이슈를 보고해볼까. 


# 참고 
- https://github.com/rajatomar788/pywebcopy
- https://github.com/rajatomar788/pywebcopy/issues/128