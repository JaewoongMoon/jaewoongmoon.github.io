---
layout: post
title: "파이썬으로 PDF 파일 메타데이터 분석하기"
categories: [포렌식, VIOLENT PYTHON]
tags: [포렌식, PDF, 메타데이터, VIOLENT PYTHON]
toc: true
last_modified_at: 2023-09-12 17:15:00 +0900
---

# 개요
- VIOLENT PYTHON 서적의 내용을 참고해서 정리한 페이지이다. 
- 유명한 해커 그룹 어나니머스가 2010년에 발표한 성명을 저장하고 있는 PDF 파일의 메타데이터를 파이썬을 사용해서 분석해본다. 
- https://www.wired.com/images_blogs/threatlevel/2010/12/ANONOPS_The_Press_Release.pdf 에서 ANONOPS_The_Press_Release.pdf를 다운로드 받는다. 

# 라이브러리 
- pypdf 를 사용한다. 

## 설치 

```
pip install pypdf
```

# 파이썬 코드 
다음 코드를 사용한다. 실행에는 파이썬3가 필요하다. 

```py
import pypdf
import optparse
from pypdf import PdfReader

def print_meta(file_name):
    pdf_file = PdfReader(file_name)
    doc_info = pdf_file.metadata
    print(f"[*] PDF MestaData for: {str(file_name)}")
    for meta_item in doc_info:
        print(f"[+] {meta_item}: {doc_info[meta_item]}")


def main():
    parser = optparse.OptionParser("usate %prog -F <PDF file name>")
    parser.add_option('-F', dest='fileName', type='string', help='specify PDF file name')
    (options, args) = parser.parse_args()
    fileName = options.fileName
    if fileName == None:
        print(parser.usage)
        exit(0)
    else:
        print_meta(fileName)

if __name__ == '__main__':
    main()
```

# 실행결과 
실행결과는 다음과 같다. 작성자의 이름이 노출되는 바람에 경찰에 잡혔다고 한다. 

```sh
python pdfRead.py -F ANONOPS_The_Press_Release.pdf
[*] PDF MestaData for: ANONOPS_The_Press_Release.pdf
[+] /Author: Alex Tapanaris
[+] /Creator: Writer
[+] /Producer: OpenOffice.org 3.2
[+] /CreationDate: D:20101210031827+02'00'
```