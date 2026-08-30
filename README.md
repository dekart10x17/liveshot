# Liveshot

**Liveshot** is a multi-threaded Go reconnaissance tool for live web target discovery, HTTP metadata probing, WAF detection, and automated headless Chrome screenshots.

---

## Usage & Flags

```text
Usage: liveshot [options]

Target Options:
  -u <url>         Single target URL
  -l <file>        Target list file (one URL per line)
  -j <file>        Target JSON file

Scan Configurations:
  -t <threads>     Number of concurrent threads (default: 10)
  -timeout <sec>   HTTP & Browser navigation timeout (default: 15)
  -mc <codes>      Match specific status codes (e.g. 200,302)
  -fc <codes>      Filter out specific status codes (e.g. 403,404)
  -x <proxies>     Single or proxy list (comma-separated)
  -ua <string>     Custom User-Agent string

Output Options:
  -no-img          Disable screenshot capture (probe-only mode)
  -live-only       Process/save live targets only
  -save-txt <file> Export live target URLs to text file
  -o <dir>         Output directory (default: timestamped report dir)
  -debug           Display browser JS console errors
```
# Examples

```./liveshot -u [https://example.com](https://example.com)```

# Fast List Probe No Screenshot 

```./liveshot -l targets.txt -no-img -t 25```

# Match 200 OK & Save Live Hosts:

```./liveshot -l targets.txt -mc 200 -save-txt live.txt```

# Installation
```git clone https://github.com/dekart10x17/liveshot.git
cd liveshot
go mod tidy
go build -o liveshot main.go
```



