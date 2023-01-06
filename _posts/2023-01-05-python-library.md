---
layout: post
title: "파이썬 라이브러리 만드는 방법"
categories: [프로그래밍, 파이썬]
tags: [프로그래밍, 파이썬, 라이브러리 만들기]
toc: true
---

# 개요 
- 파이썬으로 라이브러리 만들기 예제를 실행해본다. 
- 내 환경은 Windows, Python 3.10 이다. 
- [여기](https://medium.com/analytics-vidhya/how-to-create-a-python-library-7d5aea80cc3f){:target="_blank"} 를 참고했다. 

# 명령어 
## 라이브러리 빌드
- 라이브러리를 빌드하기 위해서는 `wheel` 과 `setuptools` 라이브러리가 필요하다. 
프로젝트 루트로 이동 후 다음 명령어 실행한다. 실행후에 dist 디렉토리가 만들어진다. 여기에 컴파일된 wheel 파일(.whl 파일)이 저장된다. 

```sh
python setup.py bdist_wheel
```

## 라이브러리를 PyPI에 업로드하기 
리포지토리에 업로드하기 위해서 `twine` 라이브러리를 사용한다. 

```sh
python -m twine upload dist/*
```

참고로 특정 리포지토리에 업로드하고 싶으면 다음과 같이 실행
```sh
python -m twine upload --repository {리포지토리명} dist/*
```


# 트러블슈팅
- 테스트 단계에서 pytest를 실행하자 `AttributeError: 'AssertionRewritingHook' object has no attribute 'find_spec'` 에러가 발생했다.  
- https://stackoverflow.com/questions/72293719/pytest-cannot-be-executed-from-python-3-10-4 를 보니 pytest의 버전이 낮은 것이 원인인 것 같다. 
- setup.py에서 pytest 버전을 7.2.0 으로 지정하자 에러가 사라졌다. 

# 참고링크
- https://medium.com/analytics-vidhya/how-to-create-a-python-library-7d5aea80cc3f
- 