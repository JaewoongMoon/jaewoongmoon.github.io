---
layout: post
title: "theHarvester 개요"
categories: [OSINT, Pentest, Kali Linux]
tags: [OSINT, Pentest, Kali Linux]
toc: true
last_modified_at: 2025-03-18 21:55:00 +0900
---


# 개요
therHarvester는 공격 대상에 대한 다양한 공개 정보를 수집하는 정찰 도구다. LinkedIn 등의 SNS, 이메일 주소, IP 주소, 도메인, URL 등을 수집한다.

# 사용법
- 커맨드 `theHarvester`는 대소문자를 구분한다. 
- `-b` 옵션이 핵심이다. 이 옵션으로 다양한 소스를 지정할 수 있다. 이 툴을 설명해주는 여러 문서들을 보면 예시에 `google`을 지정하는데, 최신버전에서는 구글검색은 빠져있다. 
- 소스가 다양하므로 각 소스에서 어떤 것을 얻을 수 있는지 조사해보는 것도 좋겠다. 

```sh
$ theHarvester -h
Read proxies.yaml from /home/kali/.theHarvester/proxies.yaml
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.6.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*                                                                 *
*******************************************************************
usage: theHarvester [-h] -d DOMAIN [-l LIMIT] [-S START] [-p] [-s] [--screenshot SCREENSHOT] [-v] [-e DNS_SERVER] [-t] [-r [DNS_RESOLVE]] [-n] [-c]
                    [-f FILENAME] [-b SOURCE]

theHarvester is used to gather open source intelligence (OSINT) on a company or domain.

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Company name or domain to search.
  -l LIMIT, --limit LIMIT
                        Limit the number of search results, default=500.
  -S START, --start START
                        Start with result number X, default=0.
  -p, --proxies         Use proxies for requests, enter proxies in proxies.yaml.
  -s, --shodan          Use Shodan to query discovered hosts.
  --screenshot SCREENSHOT
                        Take screenshots of resolved domains specify output directory: --screenshot output_directory
  -v, --virtual-host    Verify host name via DNS resolution and search for virtual hosts.
  -e DNS_SERVER, --dns-server DNS_SERVER
                        DNS server to use for lookup.
  -t, --take-over       Check for takeovers.
  -r [DNS_RESOLVE], --dns-resolve [DNS_RESOLVE]
                        Perform DNS resolution on subdomains with a resolver list or passed in resolvers, default False.
  -n, --dns-lookup      Enable DNS server lookup, default False.
  -c, --dns-brute       Perform a DNS brute force on the domain.
  -f FILENAME, --filename FILENAME
                        Save the results to an XML and JSON file.
  -b SOURCE, --source SOURCE
                        anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, brave, censys, certspotter, criminalip, crtsh, dnsdumpster,
                        duckduckgo, fullhunt, github-code, hackertarget, hunter, hunterhow, intelx, netlas, onyphe, otx, pentesttools,
                        projectdiscovery, rapiddns, rocketreach, securityTrails, sitedossier, subdomaincenter, subdomainfinderc99, threatminer,
                        tomba, urlscan, virustotal, yahoo, zoomeye

```

# 정보 소스 

|소스명|설명|URL|
|---|----|----|
|anubis|Anubis는 다양한 소스로부터 서브도메인 정보를 모아주는 툴이다. |https://github.com/jonluca/anubis|
|baidu|바이두 검색 엔진을 사용한다. |https://www.baidu.com|
|bevigil|bevigil은 수많은 모바일앱을 분석해서 그 안에서 OSINT정도를 뽑아내서 제공해주는 툴이다. API 키가 필요하다. |https://bevigil.com/osint-api|
|binaryedge|알려진 서브도메인을 찾아준다. API 키가 필요하다.|https://www.binaryedge.io/|
|bing|MS의 검색엔진인 bing 을 통해 알려진 정보를 검색한다. |https://www.bing.com/|
|bingapi| bing의 API를 통해 알려진 정보를 검색한다. API 키가 필요하다.||
|bufferoverun|IPv4 주소 공간에서 서버 증명서 정보를 검색해주는 툴이다. API 키가 필요하다. |https://tls.bufferover.run/|
|brave| brave 검색 엔진을 통해 알려진 정보를 검색한다. |https://search.brave.com/|
|censys|호스트 정보 검색 서비스를 제공하는 censys 를 사용한다. API Key가 필요하다. |https://search.censys.io/|
|certspotter|crt.sh 와 마찬가지로 CT로그를 모니터링 해주는 툴이다.|https://sslmate.com/certspotter/|
|criminalip|사이버 위협 인텔리젼스(CTI) 정보를 검색할 수 있는 검색 엔진이다. API Key가 필요하다. |https://www.criminalip.io|
|crtsh|Certificate Transparency(CT, 증명서발행이력) 정보를 토대로 도메인 정보를 찾아준다.|https://crt.sh/|
|dnsdumpster|||
|duckduckgo|duckduckgo 검색엔진을 통해 정보를 찾는다. |https://duckduckgo.com|
|fullhunt|차세대 공격 표면 보안 플랫폼이다. API Key가 필요하다.|https://fullhunt.io/|
|github-code|github 검색 엔진을 통해 정보를 찾는다. github의 개인 억세스 토큰이 필요하다. |https://github.com/|
|hackertarget|조직을 위한 취약점 스캐너 및 네트워크 정보를 제공해주는 툴이다. |https://hackertarget.com/|
|hunter|알려진 이메일을 검색해주는 검색엔진이다. API키가 필요하다. |https://hunter.io/|
|hunterhow|보안 연구자를 위한 검색엔진이다. 다양한 검색어로 검색을 할 수 있다. API 키가 필요하다. |https://hunter.how/|
|intelx|||
|netlas|||
|onyphe|||
|otx|||
|pentesttools|||
|projectdiscovery|다양한 CLI기반 스캐너 툴을 개발하는 프로젝트|https://projectdiscovery.io/|
|rapiddns|||
|rocketreach|||
|securityTrails|풍부한 도메인 정보를 조사하고 제공해주는 서비스다.|https://securitytrails.com/|
|sitedossier|||
|subdomaincenter|||
|subdomainfinderc99|||
|threatminer|||
|tomba|||
|urlscan|||
|virustotal|||
|yahoo|||
|zoomeye|||



# 참고
- https://github.com/laramies/theHarvester
- 해커는 theHarvester로 이메일, 서브도메인, 호스트, 검색엔진 등 공개소스로부터 수집한다: https://whitemarkn.com/learning-ethical-hacker/theharvester/
- Katana와 WebCralwer: https://www.hahwul.com/2022/11/09/katana-and-web-crawler/