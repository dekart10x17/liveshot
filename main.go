package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Grey   = "\033[90m"
	Bold   = "\033[1m"
)

type Result struct {
	Index         int                 `json:"index"`
	URL           string              `json:"url"`
	StatusCode    int                 `json:"status_code"`
	StatusText    string              `json:"status_text"`
	ResponseTime  int64               `json:"response_time_ms"`
	Title         string              `json:"title"`
	Server        string              `json:"server"`
	ContentType   string              `json:"content_type"`
	ContentLength string              `json:"content_length"`
	WAF           string              `json:"waf"`
	UsedProxy     string              `json:"used_proxy"`
	Image         string              `json:"image"`
	ConsoleLogs   []string            `json:"console_logs"`
	Headers       map[string][]string `json:"headers"`
}

type Config struct {
	ListFile     string
	JSONFile     string
	SingleURL    string
	Threads      int
	Timeout      int
	Proxies      string
	UserAgent    string
	OutputDir    string
	Headers      string
	MatchCodes   string
	FilterCodes  string
	Debug        bool
	FindMode     bool
	LiveOnly     bool
	NoScreenshot bool
	SaveTxt      string
}

func printUsage() {
	fmt.Println("Usage: liveshot [options]")
	fmt.Println("  -u <url>         Target URL")
	fmt.Println("  -l <file>        Target list")
	fmt.Println("  -mc <codes>      Match status codes (e.g. 200,302)")
	fmt.Println("  -fc <codes>      Filter status codes (e.g. 403,404)")
	fmt.Println("  -t <threads>     Threads (default: 10)")
	fmt.Println("  -timeout <sec>   Timeout (default: 15)")
	fmt.Println("  -live-only       Process live hosts only")
	fmt.Println("  -no-img          Disable screenshots")
	fmt.Println("  -save-txt <file> Export live targets to file")
	fmt.Println("  -o <dir>         Output directory (default: timestamped report dir)")
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		printUsage()
		os.Exit(1)
	}

	if cfg.OutputDir == "" {
		now := time.Now()
		folderName := fmt.Sprintf("report %s", now.Format("15.04_02.01.06"))
		cfg.OutputDir = folderName
	}

	urls := loadTargets(cfg)
	if len(urls) == 0 {
		fmt.Printf("%s[!] Error: No targets loaded.%s\n", Red, Reset)
		os.Exit(1)
	}

	proxyList := []string{}
	if cfg.Proxies != "" {
		for _, p := range strings.Split(cfg.Proxies, ",") {
			if strings.TrimSpace(p) != "" {
				proxyList = append(proxyList, strings.TrimSpace(p))
			}
		}
	}

	matchMap := parseCodeList(cfg.MatchCodes)
	filterMap := parseCodeList(cfg.FilterCodes)

	imgDir := filepath.Join(cfg.OutputDir, "screenshots")
	if !cfg.NoScreenshot {
		os.MkdirAll(imgDir, os.ModePerm)
	}

	fmt.Printf("Starting liveshot at %s\n", time.Now().Format("2006-01-02 15:04 MST"))
	fmt.Printf("Initiating scan on %d targets using %d threads...\n\n", len(urls), cfg.Threads)

	targetsChan := make(chan struct {
		Index int
		URL   string
	}, len(urls))

	resultsChan := make(chan Result, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetsChan {
				selectedProxy := ""
				if len(proxyList) > 0 {
					selectedProxy = proxyList[rand.Intn(len(proxyList))]
				}

				var res Result
				if cfg.NoScreenshot {
					res = probeOnly(target.URL, target.Index, cfg.Timeout, selectedProxy)
				} else {
					res = capture(target.URL, target.Index, imgDir, cfg.Timeout, cfg.UserAgent, cfg.Headers, selectedProxy)
				}

				if cfg.LiveOnly && res.StatusCode == 0 {
					continue
				}
				if len(matchMap) > 0 && !matchMap[res.StatusCode] {
					continue
				}
				if len(filterMap) > 0 && filterMap[res.StatusCode] {
					continue
				}

				resultsChan <- res

				statusColor := Green
				if res.StatusCode >= 400 {
					statusColor = Red
				} else if res.StatusCode >= 300 {
					statusColor = Yellow
				}

				fmt.Printf("[%s%d%s] %s | %s%s%s (%dms) | %s%s%s\n",
					statusColor, res.StatusCode, Reset,
					res.URL,
					Grey, res.Server, Reset,
					res.ResponseTime,
					Bold, res.Title, Reset,
				)

				if cfg.Debug && len(res.ConsoleLogs) > 0 {
					for _, logMsg := range res.ConsoleLogs {
						fmt.Printf("   \\_ [debug] %s\n", logMsg)
					}
				}
			}
		}()
	}

	for idx, url := range urls {
		targetsChan <- struct {
			Index int
			URL   string
		}{Index: idx + 1, URL: url}
	}
	close(targetsChan)

	wg.Wait()
	close(resultsChan)

	var results []Result
	var txtLines []string

	for r := range resultsChan {
		results = append(results, r)
		txtLines = append(txtLines, r.URL)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Index < results[j].Index
	})

	os.MkdirAll(cfg.OutputDir, os.ModePerm)
	jsonBytes, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(filepath.Join(cfg.OutputDir, "results.json"), jsonBytes, 0644)

	if cfg.SaveTxt != "" {
		os.WriteFile(cfg.SaveTxt, []byte(strings.Join(txtLines, "\n")), 0644)
	}

	generateHTMLReport(results, cfg.OutputDir)

	absPath, err := filepath.Abs(cfg.OutputDir)
	if err != nil {
		absPath = cfg.OutputDir
	}

	fmt.Printf("\nScan completed: %d hosts up.\n", len(results))
	fmt.Printf("Results directory: %s\n", absPath)
}

func parseFlags() (Config, error) {
	var cfg Config
	flagSet := flag.NewFlagSet("liveshot", flag.ContinueOnError)
	flagSet.SetOutput(os.Stderr)

	flagSet.StringVar(&cfg.ListFile, "l", "", "")
	flagSet.StringVar(&cfg.JSONFile, "j", "", "")
	flagSet.StringVar(&cfg.SingleURL, "u", "", "")
	flagSet.IntVar(&cfg.Threads, "t", 10, "")
	flagSet.IntVar(&cfg.Timeout, "timeout", 15, "")
	flagSet.StringVar(&cfg.Proxies, "x", "", "")
	flagSet.StringVar(&cfg.UserAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "")
	flagSet.StringVar(&cfg.OutputDir, "o", "", "")
	flagSet.StringVar(&cfg.Headers, "H", "", "")
	flagSet.StringVar(&cfg.MatchCodes, "mc", "", "")
	flagSet.StringVar(&cfg.FilterCodes, "fc", "", "")
	flagSet.BoolVar(&cfg.Debug, "debug", false, "")
	flagSet.BoolVar(&cfg.FindMode, "find", false, "")
	flagSet.BoolVar(&cfg.LiveOnly, "live-only", false, "")
	flagSet.BoolVar(&cfg.NoScreenshot, "no-img", false, "")
	flagSet.StringVar(&cfg.SaveTxt, "save-txt", "", "")

	flagSet.Usage = printUsage

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		return cfg, err
	}

	if cfg.FindMode {
		cfg.NoScreenshot = true
		cfg.LiveOnly = true
	}

	if cfg.SingleURL == "" && cfg.ListFile == "" && cfg.JSONFile == "" {
		return cfg, fmt.Errorf("missing target")
	}

	return cfg, nil
}

func parseCodeList(raw string) map[int]bool {
	m := make(map[int]bool)
	if raw == "" {
		return m
	}
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		code, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil {
			m[code] = true
		}
	}
	return m
}

func loadTargets(cfg Config) []string {
	var raw []string
	if cfg.SingleURL != "" {
		raw = append(raw, cfg.SingleURL)
	} else if cfg.ListFile != "" {
		fileBytes, err := os.ReadFile(cfg.ListFile)
		if err != nil {
			return nil
		}
		fileBytes = bytes.TrimPrefix(fileBytes, []byte("\xef\xbb\xbf"))
		scanner := bufio.NewScanner(bytes.NewReader(fileBytes))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = strings.Trim(line, "\r\n\t ")
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "{\\rtf") {
				raw = append(raw, line)
			}
		}
	} else if cfg.JSONFile != "" {
		data, err := os.ReadFile(cfg.JSONFile)
		if err == nil {
			json.Unmarshal(data, &raw)
		}
	}

	var formatted []string
	for _, u := range raw {
		uClean := strings.TrimSpace(u)
		if uClean == "" {
			continue
		}
		if !strings.HasPrefix(uClean, "http://") && !strings.HasPrefix(uClean, "https://") {
			formatted = append(formatted, "https://"+uClean)
		} else {
			formatted = append(formatted, uClean)
		}
	}
	return formatted
}

func probeOnly(targetURL string, index int, timeoutSec int, proxyStr string) Result {
	startTime := time.Now()
	statusCode := 0
	statusText := "Timeout"
	serverHeader := "N/A"
	contentType := "N/A"
	contentLength := "N/A"
	wafDetected := "None"
	respHeaders := make(map[string][]string)

	goProbe(targetURL, proxyStr, timeoutSec, &statusCode, &statusText, &serverHeader, &contentType, &contentLength, &wafDetected, respHeaders)
	elapsedTime := time.Since(startTime).Milliseconds()

	return Result{
		Index:         index,
		URL:           targetURL,
		StatusCode:    statusCode,
		StatusText:    statusText,
		ResponseTime:  elapsedTime,
		Title:         "N/A",
		Server:        serverHeader,
		ContentType:   contentType,
		ContentLength: contentLength,
		WAF:           wafDetected,
		UsedProxy:     proxyStr,
		Image:         "",
		Headers:       respHeaders,
	}
}

func capture(targetURL string, index int, imgDir string, timeoutSec int, userAgent string, customHeaders string, proxyStr string) Result {
	startTime := time.Now()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.UserAgent(userAgent),
	)

	if proxyStr != "" {
		opts = append(opts, chromedp.ProxyServer(proxyStr))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, time.Duration(timeoutSec+5)*time.Second)
	defer cancelTimeout()

	imgName := fmt.Sprintf("%d.png", index)
	imgPath := filepath.Join(imgDir, imgName)

	var buf []byte
	var title string
	statusCode := 0
	statusText := "Timeout"
	serverHeader := "N/A"
	contentType := "N/A"
	contentLength := "N/A"
	wafDetected := "None"
	respHeaders := make(map[string][]string)
	var consoleLogs []string
	var consoleMutex sync.Mutex

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			var args []string
			for _, arg := range ev.Args {
				args = append(args, string(arg.Value))
			}
			consoleMutex.Lock()
			consoleLogs = append(consoleLogs, fmt.Sprintf("[%s] %s", ev.Type, strings.Join(args, " ")))
			consoleMutex.Unlock()
		}
	})

	goProbe(targetURL, proxyStr, timeoutSec, &statusCode, &statusText, &serverHeader, &contentType, &contentLength, &wafDetected, respHeaders)

	tasks := chromedp.Tasks{
		chromedp.EmulateViewport(1280, 800),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2 * time.Second),
		chromedp.Title(&title),
		chromedp.CaptureScreenshot(&buf),
	}

	err := chromedp.Run(ctx, tasks)
	elapsedTime := time.Since(startTime).Milliseconds()

	if len(buf) > 0 {
		os.WriteFile(imgPath, buf, 0644)
	} else {
		imgName = ""
	}

	if title == "" {
		title = "N/A"
	}

	if err != nil && statusCode == 0 && len(buf) == 0 {
		return Result{
			Index:        index,
			URL:          targetURL,
			StatusCode:   0,
			StatusText:   "Error",
			ResponseTime: elapsedTime,
			Title:        "N/A",
			WAF:          "None",
			UsedProxy:    proxyStr,
			ConsoleLogs:  consoleLogs,
		}
	}

	return Result{
		Index:         index,
		URL:           targetURL,
		StatusCode:    statusCode,
		StatusText:    statusText,
		ResponseTime:  elapsedTime,
		Title:         title,
		Server:        serverHeader,
		ContentType:   contentType,
		ContentLength: contentLength,
		WAF:           wafDetected,
		UsedProxy:     proxyStr,
		Image:         imgName,
		ConsoleLogs:   consoleLogs,
		Headers:       respHeaders,
	}
}

func goProbe(targetURL string, proxyStr string, timeoutSec int, statusCode *int, statusText *string, server *string, cType *string, cLen *string, waf *string, headers map[string][]string) {
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	*statusCode = resp.StatusCode
	if len(resp.Status) > 4 {
		*statusText = resp.Status[4:]
	} else {
		*statusText = http.StatusText(resp.StatusCode)
	}

	*server = resp.Header.Get("Server")
	if *server == "" {
		*server = "N/A"
	}

	*cType = resp.Header.Get("Content-Type")
	if *cType == "" {
		*cType = "N/A"
	}

	*cLen = resp.Header.Get("Content-Length")
	if *cLen == "" {
		*cLen = "N/A"
	}

	sHeader := strings.ToLower(*server)
	if strings.Contains(sHeader, "cloudflare") || resp.Header.Get("cf-ray") != "" {
		*waf = "Cloudflare"
	} else if strings.Contains(sHeader, "akamai") || resp.Header.Get("x-akamai-transformed") != "" {
		*waf = "Akamai"
	} else if resp.Header.Get("x-amz-cf-id") != "" {
		*waf = "AWS CloudFront WAF"
	} else if strings.Contains(sHeader, "imperva") || resp.Header.Get("x-iinfo") != "" {
		*waf = "Imperva"
	}
}

func generateHTMLReport(results []Result, outputDir string) {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Targets</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { 
            background-color: #0d0e11; 
            color: #adbac7; 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            font-size: 12px;
        }
        .top-bar {
            background-color: #161b22;
            border-bottom: 1px solid #21262d;
            padding: 8px 16px;
        }
        .card { 
            background-color: #161b22; 
            border: 1px solid #30363d; 
            border-radius: 4px;
        }
        .card-header {
            background-color: #0d1117 !important;
            border-bottom: 1px solid #21262d;
            font-size: 11px;
            padding: 6px 12px;
        }
        .img-box { 
            height: 160px; 
            background: #010409; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            border-top: 1px solid #21262d; 
            cursor: pointer; 
        }
        .img-box img { 
            width: 100%; 
            height: 100%; 
            object-fit: cover; 
            opacity: 0.8;
        }
        .img-box img:hover {
            opacity: 1;
        }
        .url-link { 
            color: #58a6ff; 
            text-decoration: none; 
            font-weight: 600;
            word-break: break-all; 
        }
        .search-box { 
            background: #0d1117; 
            border: 1px solid #30363d; 
            color: #c9d1d9; 
            font-size: 12px;
            padding: 4px 8px;
        }
        .search-box:focus { 
            background: #0d1117; 
            color: #c9d1d9; 
            border-color: #58a6ff; 
            box-shadow: none; 
        }
        .btn-status {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 3px;
        }
        .modal-body img { 
            width: 100%; 
            height: auto; 
        }
        .modal-content { 
            background-color: #161b22; 
            border: 1px solid #30363d; 
        }
    </style>
</head>
<body>
    <div class="top-bar d-flex justify-content-between align-items-center mb-3">
        <span class="fw-bold text-light">Targets ({{len .}})</span>
        <input type="text" id="searchInput" class="form-control search-box w-25" placeholder="Filter targets...">
    </div>

    <div class="container-fluid px-3">
        <div class="row g-2" id="grid">
            {{range .}}
            <div class="col-xl-3 col-lg-4 col-md-6 card-item" data-search="{{.URL}} {{.Title}} {{.StatusCode}} {{.Server}}">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="text-secondary">#{{.Index}}</span>
                        <div>
                            {{if ne .WAF "None"}}<span class="badge bg-secondary me-1">{{.WAF}}</span>{{end}}
                            <span class="badge {{if ge .StatusCode 400}}bg-danger{{else if ge .StatusCode 300}}bg-warning text-dark{{else}}bg-success{{end}}">{{.StatusCode}}</span>
                        </div>
                    </div>
                    <div class="card-body p-2">
                        <a href="{{.URL}}" target="_blank" class="url-link">{{.URL}}</a>
                        <div class="text-secondary mt-1 text-truncate" title="{{.Title}}">Title: {{.Title}}</div>
                        <div class="text-secondary text-truncate">Server: {{.Server}}</div>
                    </div>
                    <div class="img-box" {{if .Image}}onclick="openModal('screenshots/{{.Image}}', '{{.URL}}')"{{end}}>
                        {{if .Image}}
                        <img src="screenshots/{{.Image}}" loading="lazy" alt="Screenshot">
                        {{else}}
                        <span class="text-secondary small">[ No Image ]</span>
                        {{end}}
                    </div>
                </div>
            </div>
            {{end}}
        </div>
    </div>

    <div class="modal fade" id="imageModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-xl modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header border-secondary p-2">
                    <span class="modal-title text-light small" id="modalTitle"></span>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body text-center p-1">
                    <img id="modalImage" src="" alt="Preview">
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('searchInput').addEventListener('keyup', function() {
            let filter = this.value.toLowerCase();
            document.querySelectorAll('.card-item').forEach(card => {
                let text = card.getAttribute('data-search').toLowerCase();
                card.style.display = text.includes(filter) ? '' : 'none';
            });
        });

        function openModal(imgSrc, url) {
            document.getElementById('modalImage').src = imgSrc;
            document.getElementById('modalTitle').innerText = url;
            let modal = new bootstrap.Modal(document.getElementById('imageModal'));
            modal.show();
        }
    </script>
</body>
</html>`

	tmpl, _ := template.New("dashboard").Parse(htmlTemplate)
	filePath := filepath.Join(outputDir, "index.html")
	file, _ := os.Create(filePath)
	defer file.Close()
	tmpl.Execute(file, results)
}