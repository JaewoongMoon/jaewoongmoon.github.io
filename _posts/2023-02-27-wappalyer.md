---
layout: post
title: "Wappalyzer(와팔라이저) 설치 및 사용법"
categories: [보안툴, 스캐너, 웹사용기술스택조사]
tags: [보안툴, 스캐너, 웹사용기술스택조사]
toc: true
---

# Wappalyzer란? 
- Wappalyzer(와팔라이저)는 웹 페이지를 분석해서 웹 사이트가 어떤 기술스택을 사용해서 만들어졌는지를 알려주는 오픈 소스 툴이다. 
- 웹 서버 종류나 버전, 사용중인 웹 프레임워크나 자바 스크립트 라이브러리 버전 등을 알려준다. 
- 크롬 확장 프로그램으로 설치하는 방법과 PC에 설치해서 쓰는 방법이 있다. 
- 크롬 확장 프로그램이 사용하기는 쉽지만 매번 웹 사이트를 방문해서 확장 프로그램을 실시해야 하는 번거로움이 있다. 
- 설치형은 설치 과정이 번거롭지만 스크립트와 연동해서 많은 수의 사이트를 한번에 돌릴 수 있는 장점이 있다. 
- 이 포스트에서는 설치형을 정리한다. 
- Wappalyzer는 Node.js로 개발되었다. npm이나 yarn을 통해 설치가 가능하다. 

## 장점(어디에 쓸 것인가?)
- 여러 가지 방면에서 사용할 수 있겠지만, 내 경우에는 취약점 대응 범위를 특정하는데 사용할 수 있다고 본다. 
- 예를들어, 어떤 CMS(wordpress등)에만 존재하는 취약점이 있다고 할 때, 미리 사용기술을 분석해두면, wordpress를 사용하고 있는 서버만 추려서 취약점 테스트를 해볼 수 있다. 

## 사용 기술을 알아내는 원리 
- 내부적으로 웹 페이지에 접근하는 브라우저로 chromium을 사용하는 것 같다. 
- 미리 정의된 시그니쳐 같은 것을 가지고 있다. (https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies)
- 웹 페이지를 크롤링해서 매치되는 것을 찾으면 해당 기술을 사용해서 구축하고 있다고 판단하는 것 같다. 

예를들면, 다음과 같은 식이다. 특정 경로에 특정 파일이 존재하는 것으로 판단한다. 

```json
 "WP Maintenance Mode": {
    "cats": [
      87
    ],
    "description": "WP Maintenance Mode is a WordPress plugin which add a maintenance page to your blog.",
    "icon": "WP Maintenance Mode.png",
    "js": {
      "wpmm_vars": ""
    },
    "oss": true,
    "requires": "WordPress",
    "scriptSrc": "/wp-content/plugins/wp-maintenance-mode/.+wpmm\\.js(?:\\?ver=(\\d+(?:\\.\\d+)+))?\\;version:\\1",
    "website": "https://github.com/andrianvaleanu/WP-Maintenance-Mode"
  }
```

또는 다음과 같은 식으로 특정 메타태그가 존재하는지 여부로 판단하기도 한다. 

```json
 "WebGUI": {
    "cats": [
      1
    ],
    "cookies": {
      "wgSession": ""
    },
    "icon": "WebGUI.png",
    "implies": "Perl",
    "meta": {
      "generator": "^WebGUI ([\\d.]+)\\;version:\\1"
    },
    "website": "http://www.webgui.org"
  },
```

그리고 각 기술의 아이콘을 가지고 있다. 크롬 확장 프로그램에서는 이 아이콘을 사용해서 사용기술목록을 출력해준다. (https://github.com/wappalyzer/wappalyzer/tree/master/src/drivers/webextension/images/icons)


# 설치방법
## npm 으로 설치 
- npm을 통한 설치가 가장 간편했다. 

```sh
npm i wappalyzer
```

# 사용법
## 커맨드 라인으로 사용
다음과 같이 커맨드 라인으로 사용가능하다. 

```sh 
wappalyzer
Usage:
  wappalyzer <url> [options]

Examples:
  wappalyzer https://www.example.com
  node cli.js https://www.example.com -r -D 3 -m 50 -H "Cookie: username=admin"
  docker wappalyzer/cli https://www.example.com --pretty

Options:
  -b, --batch-size=...       Process links in batches
  -d, --debug                Output debug messages
  -t, --delay=ms             Wait for ms milliseconds between requests
  -h, --help                 This text
  -H, --header               Extra header to send with requests
  --html-max-cols=...        Limit the number of HTML characters per line processed
  --html-max-rows=...        Limit the number of HTML lines processed
  -D, --max-depth=...        Don't analyse pages more than num levels deep
  -m, --max-urls=...         Exit when num URLs have been analysed
  -w, --max-wait=...         Wait no more than ms milliseconds for page resources to load
  -p, --probe=[basic|full]   Perform a deeper scan by performing additional requests and inspecting DNS records
  -P, --pretty               Pretty-print JSON output
  --proxy=...                Proxy URL, e.g. 'http://user:pass@proxy:8080'
  -r, --recursive            Follow links on pages (crawler)
  -a, --user-agent=...       Set the user agent string
  -n, --no-scripts           Disabled JavaScript on web pages
  -N, --no-redirect          Disable cross-domain redirects
  -e, --extended             Output additional information
  --local-storage=...        JSON object to use as local storage
  --session-storage=...      JSON object to use as session storage
```

## Node.js 라이브러리로 사용
- Node.js 프로그램에서 wappalyzer라이브러리를 호출해서 사용할 수도 있다. 
- 추가로 프로그래밍을 해서 사용한다면 이 방법이 좋을 수도 있다. 
- 다음 링크에 Node.js 프로그램에서 라이브러리로 사용하는 경우의 샘플이 실려있다. 
- https://www.npmjs.com/package/wappalyzer
- 

```js
const Wappalyzer = require('wappalyzer');
 
const url = 'https://www.some-url.com';
 
const options = {
  debug: false,
  delay: 500,
  headers: {},
  maxDepth: 3,
  maxUrls: 10,
  maxWait: 5000,
  recursive: true,
  probe: true,
  proxy: false,
  userAgent: 'Wappalyzer',
  htmlMaxCols: 2000,
  htmlMaxRows: 2000,
  noScripts: false,
  noRedirect: false,
};
 
const wappalyzer = new Wappalyzer(options)
 
;(async function() {
  try {
    await wappalyzer.init()
 
    // Optionally set additional request headers
    const headers = {}
 
    const site = await wappalyzer.open(url, headers)
 
    // Optionally capture and output errors
    site.on('error', console.error)
 
    const results = await site.analyze()
 
    console.log(JSON.stringify(results, null, 2))
  } catch (error) {
    console.error(error)
  }
 
  await wappalyzer.destroy()
})()
```

# 결과 포맷
- 결과는 json 형식으로 출력된다. 
- 스펙은 [여기](https://www.wappalyzer.com/docs/dev/specification/)에서 확인할 수 있다. 
- 몇 가지 특징적인 것을 정리해둔다. 

## cpe
- `CPE(Common Platform Enumeration)`는, IT제품이나 플랫폼을 구분하기 위한, 컴퓨터가 읽기 쉬운 식별자이다.  
- https://cpe.mitre.org/about/


# 트러블슈팅
## 실행시 크롬 관련 에러가 발생하는 경우 
다음과 같은 에러가 발생했다. 

```sh
node_modules/puppeteer/.local-chromium/linux-991974/chrome-linux/chrome: error while loading shared libraries: libatk-1.0.so.0: cannot open shared object file: No such file or directory


TROUBLESHOOTING: https://github.com/puppeteer/puppeteer/blob/main/docs/troubleshooting.md

```

### 원인분석
- wappalyer는 의존 라이브러리로 Puppeteer를 사용하는데, Puppeteer를 구동하는데 필요한 libatk라이브러리가 설치되지 않은 것 같다. 
- node_modules/puppeteer/ 경로로 이동해서 확인해보니 아예 .local-chromium 경로자체가 존재하지 않았다. (로컬 PC에 설치한 puppeteer에는 존재했다.) 
- 리눅스 서버에 설치된 Puppeteer 버전은 최신버전인 19.7.2였고, PC에 설치된 버전은 14.1.2였다. PC설치버전이 더 오래된 버전이었다.
- 

### 수동으로 chromium 설치
- https://stackoverflow.com/questions/48480143/installing-chromium-on-amazon-linux
- https://cloud.google.com/looker/docs/best-practices/how-to-install-chromium-for-amazon-linux
- 의존라이브러리 설치를 위해서는 `amazon-linux-extras` 가 필요한데 아마존 리눅스1에서는 동작하지 않는 것 같다. 아마존 리눅스 2에서 사용가능하다고 한다. 




# 참고
- https://github.com/wappalyzer/wappalyzer
- https://www.npmjs.com/package/wappalyzer



