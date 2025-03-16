---
layout: post
title: "파이썬 Pillow 라이브러리로 이미지 파일 XMP 메타데이터 분석하기"
categories: [파이썬, 포렌식]
tags: [파이썬, 포렌식]
toc: true
last_modified_at: 2024-11-12 09:33:00 +0900
---

# 개요
조사를 통해 이미지 파일의 xmp 메타데이터를 분석하는 방법은 `XMP Toolkit`을 사용하는 방법 이외에도 있다는 것을 알게 되었다. 

# Pillow (PIL)을 사용한 방법
Pillow 8.2.0 이상을 사용하면 간단하게 xmp 메타데이터를 분석할 수 있다. 

다음 코드를 보자. 아주 간단하지 않은가? 

```py
from PIL import Image

imgFile = Image.open(image_file_path)
xmp_info = imgFile.getxmp()
print(xmp_info)
    
```

# 결론
XMP 데이터를 읽고 "쓰기"까지 하고 싶다면 `XMP Toolkit`을, 읽기만으로 충분하다면 `Pillow`(8.2.0 이상)을 사용하자. 

# 참고한 곳
- getxmp 메서드의 존재를 알려준 곳: https://stackoverflow.com/questions/6822693/read-image-xmp-data-in-python
- xmp 파싱 기능에 대한 요청: https://github.com/python-pillow/Pillow/issues/5076
- XMP 스펙: https://archimedespalimpsest.net/Documents/External/XMP/XMPSpecificationPart3.pdf
- XMP 스펙: https://www.tranquillitybase.jp/PME/userguide/xmp.html
- XMP 내부의 GPS관련 태그 정보: https://exiftool.org/forum/index.php?topic=12836.0