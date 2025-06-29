---
layout: post
title: "Metagoofil 개요"
categories: [OSINT, Pentest, Kali Linux]
tags: [OSINT, Pentest, Kali Linux]
toc: true
last_modified_at: 2025-03-18 21:55:00 +0900
---


# 개요
- metagoofil은 Google 검색을 이용하여 타겟 사이트에 존재하는 특정 확장명의 문서를 찾아주는 도구다. 
- OSS이고, Python3로 작성되었다. 

# 특징
- 파일의 메타데이터를 찾아주지는 않는다. 메타데이터를 조사하려면 exiftool 같은 다른 툴을 사용해야 한다. 
- 왜인지 설명과 달리 다운로드까지는 해주지 않았다. 
- 파일을 찾는 것은 Google 검색에 의존하기 때문에 Google에 인덱싱되지 않은 파일을 찾을 수 없다는 것에 주의할 필요가 있다. 예를 들어, `pywebcopy` 툴을 사용하면 웹 페이지의 링크를 통해 찾을 수 있는 파일을 metagoofil은 찾지 못하는 경우가 있다. 

# 설치

```sh
sudo apt install metagoofil
```

※ Kali Linux에는 기본적으로 설치되어 있다. 


# 사용법

- `l`: Google 검색으로 찾는 파일의 최대수
- `n`: 다운로드할 파일의 최대 수 

```sh
$ metagoofil -h
usage: metagoofil.py [-h] -d DOMAIN [-e DELAY] [-f [SAVE_FILE]] [-i URL_TIMEOUT] [-l SEARCH_MAX] [-n DOWNLOAD_FILE_LIMIT] [-o SAVE_DIRECTORY]
                     [-r NUMBER_OF_THREADS] -t FILE_TYPES [-u [USER_AGENT]] [-w]

Metagoofil v1.2.0 - Search Google and download specific file types.

options:
  -h, --help            show this help message and exit
  -d DOMAIN             Domain to search.
  -e DELAY              Delay (in seconds) between searches. If it's too small Google may block your IP, too big and your search may take a while.
                        Default: 30.0
  -f [SAVE_FILE]        Save the html links to a file.
                        no -f = Do not save links
                        -f = Save links to html_links_<TIMESTAMP>.txt
                        -f SAVE_FILE = Save links to SAVE_FILE
  -i URL_TIMEOUT        Number of seconds to wait before timeout for unreachable/stale pages. Default: 15
  -l SEARCH_MAX         Maximum results to search. Default: 100
  -n DOWNLOAD_FILE_LIMIT
                        Maximum number of files to download per filetype. Default: 100
  -o SAVE_DIRECTORY     Directory to save downloaded files. Default is current working directory, "."
  -r NUMBER_OF_THREADS  Number of downloader threads. Default: 8
  -t FILE_TYPES         file_types to download (pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx). To search all 17,576 three-letter file extensions, type "ALL"
  -u [USER_AGENT]       User-Agent for file retrieval against -d domain.
                        no -u = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
                        -u = Randomize User-Agent
                        -u "My custom user agent 2.0" = Your customized User-Agent
  -w                    Download the files, instead of just viewing search results.

```

# 커맨드 예

```sh
metagoofil -d {TARGET_DOMAIN} -t pdf -l 100 -n 100 -o {OUTPUT_FOLDER} -f {OUTPUT_FILE_NAME}.html
```



# 참고
- 해커는 metagoofil을 이용해서 웹 사이트 파일의 메타정보를 수집한다: https://whitemarkn.com/learning-ethical-hacker/metagoofil/#google_vignette
- 귀하의 회사는 괜찮습니까? ~메타데이터의 함정~: https://blog.nflabs.jp/entry/2021/12/17/094635
- https://www.kali.org/tools/metagoofil/
- https://github.com/opsdisk/metagoofil