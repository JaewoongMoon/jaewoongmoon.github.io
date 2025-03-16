---
layout: post
title: "파이썬 XMP Toolkit 라이브러리로 이미지 파일 XMP 메타데이터 분석하기"
categories: [파이썬, 포렌식]
tags: [파이썬, 포렌식]
toc: true
last_modified_at: 2024-11-11 09:33:00 +0900
---


# 개요
- 이미지 파일등에 XMP 메타데이터가 포함되어 있는 경우가 있다. 
- 파이썬을 라이브러리인 `XMP Toolkit`을 사용해서 이미지 파일로부터 XMP 메타데이터를 읽는 방법을 정리해둔다. 

# 전제조건
- `Exempi` 라이브러리 버전 2.2.0 이상이 필요하다. 
- 문제는 이 라이브러리가 윈도우즈용이 존재하지 않는다는 점이다. [여기](https://python-xmp-toolkit.readthedocs.io/en/latest/installation.html)를 보면 Cygwin을 사용해서 DLL로 빌드하면 사용할 수 있다고는 하나 복잡해보이므로 패스했다. 
- 리눅스 환경에서 설치하고 테스트하는게 정신건강에 좋아 보인다. 

※ 윈도우즈에서도 `XMP Toolkit` 라이브러리가 설치는 되지만 사용하려고 하면 다음과 같은 에러가 발생한다. 

```sh
File "C:\Python310\lib\site-packages\libxmp\exempi.py", line 60, in _load_exempi
    raise ExempiLoadError('Exempi library not found.')
libxmp.ExempiLoadError: Exempi library not found.
```

## Exempi 설치

### Ubuntu/Debian, OS X
Ubuntu/Debian 이나 OS X 라면 설치가 쉽다. 패키지 매니저를 사용해서 편하게 설치할 수 있다. 

```sh
sudo apt-get install libexempi3  # (Ubuntu/Debian)
brew install exempi  # (Homebrew on OS X)
```

### 다른 리눅스 
다음과정으로 설치한다. 설치중 에러가 발생할 수도 있다. 

```sh
wget https://libopenraw.freedesktop.org/download/exempi-2.2.2.tar.bz2
tar -xvf exempi-2.2.2.tar.bz2
./configure
make
sudo make install
```

### 아마존 리눅스2 

```sh
wget https://cdn.amazonlinux.com/2/core/2.0/x86_64/6b0225ccc542f3834c95733dcf321ab9f1e77e6ca6817469771a8af7c49efe6c/../../../../../blobstore/3f17b8678f5f5640dcd8e2734f00f5102a4fb075f7b66f21f72becdff619b2c5/exempi-2.2.0-9.amzn2.x86_64.rpm
sudo rpm -ivh exempi-2.2.0-9.amzn2.x86_64.rpm
```

# XMP Toolkit 설치
pip을 이용해서 설치한다. 

```sh
python3 -m pip install python-xmp-toolkit
```

# 사용법

## 파일로부터 메타데이터 읽기

```py
from libxmp import XMPFiles, consts
xmpfile = XMPFiles( file_path="test/samples/BlueSquare.jpg", open_forupdate=True )
xmp = xmpfile.get_xmp()
xmp
```

# 기타
- 이 라이브러리는 메터데이터에 포함되어 있는 다국어 데이터 표시도 제대로 해줘서 좋다! 
- 예를들어 Burp Suite같은 툴로 이미지 파일의 내용을 봤을 때 알파벳이 아니라서 글자가 깨져서 보이는 부분도 `XMP Toolkit`을 사용해서 보면 무슨 글자인지 보여준다. 


# 참고한 곳
- https://python-xmp-toolkit.readthedocs.io/en/latest/using.html
- https://qiita.com/XPT60/items/6583e747193705a42f20