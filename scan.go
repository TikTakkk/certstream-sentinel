package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	numWorkers        = 300
	timeout           = 8 * time.Second
	taskBufferFactor  = 50 // numWorkers * taskBufferFactor = 15000
	seenPurgeInterval = 2 * time.Hour
	seenExpiry        = 24 * time.Hour
)

type VulnCheck struct {
	Path        string
	Keyword     string
	OutputDir   string
	DisplayName string
	ContentType string
}

var checks = []VulnCheck{
	{"/.env", "APP_KEY", "vulnerable_env", ".env", ""},
	{"/.git/config", "[core]", "vulnerable_git", ".git", ""},
	{"/phpinfo.php", "PHP Version", "vulnerable_phpinfo", "phpinfo.php", "text/html"},
}

// SafeSeen : thread-safe map with timestamps and purge capability
type SafeSeen struct {
	mu   sync.RWMutex
	data map[string]int64
}

func NewSafeSeen() *SafeSeen { return &SafeSeen{data: make(map[string]int64)} }

func (s *SafeSeen) LoadOrStore(key string) (exists bool) {
	now := time.Now().Unix()
	s.mu.Lock()
	_, exists = s.data[key]
	if !exists {
		s.data[key] = now
	}
	s.mu.Unlock()
	return exists
}

func (s *SafeSeen) PurgeOlder(d time.Duration) {
	threshold := time.Now().Add(-d).Unix()
	s.mu.Lock()
	for k, ts := range s.data {
		if ts <= threshold {
			delete(s.data, k)
		}
	}
	s.mu.Unlock()
}

func (s *SafeSeen) Len() int {
	s.mu.RLock()
	l := len(s.data)
	s.mu.RUnlock()
	return l
}

func fetchSubdomains(domain string, client *http.Client, subCount *int64) []string {
	url := fmt.Sprintf("https://api.example.com/?domain=%s", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp == nil || resp.StatusCode != 200 {
		return nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var parsed struct {
		Result struct {
			Domains []string `json:"domains"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return nil
	}
	if len(parsed.Result.Domains) > 0 {
		atomic.AddInt64(subCount, int64(len(parsed.Result.Domains)))
	}
	return parsed.Result.Domains
}

func tryGetURLWithClient(domain string, check VulnCheck, client *http.Client) string {
	for _, scheme := range []string{"https://", "http://"} {
		url := scheme + domain + check.Path
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		cancel()
		if err != nil || resp == nil || resp.StatusCode != 200 {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			continue
		}
		if check.ContentType != "" && !strings.Contains(resp.Header.Get("Content-Type"), check.ContentType) {
			resp.Body.Close()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), check.Keyword) {
			return url
		}
	}
	return ""
}

func main() {
	// Désactiver les logs globaux (net/http etc.)
	log.SetOutput(io.Discard)

	// Préparation fichiers/writers
	writers := make(map[string]*bufio.Writer)
	filesOut := make(map[string]*os.File)
	counts := make(map[string]*int64)

	for _, check := range checks {
		_ = os.MkdirAll(check.OutputDir, os.ModePerm)
		f, err := os.OpenFile(filepath.Join(check.OutputDir, "domains_vulns.txt"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			// silently skip if file can't be opened
			continue
		}
		filesOut[check.Path] = f
		writers[check.Path] = bufio.NewWriterSize(f, 4*1024)
		var c int64
		counts[check.Path] = &c
	}

	_ = os.MkdirAll("domaine", os.ModePerm)
	domainFile, err := os.OpenFile("domaine/domaine.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// cannot proceed properly without domain file - but continue silently
	}
	domainWriter := bufio.NewWriterSize(domainFile, 4*1024)

	var scannedCount int64
	var subCount int64

	tasks := make(chan string, numWorkers*taskBufferFactor)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := NewSafeSeen()

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Purge seen périodique + GC
	go func() {
		for {
			time.Sleep(seenPurgeInterval)
			seen.PurgeOlder(seenExpiry)
			runtime.GC()
		}
	}()

	// Workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range tasks {
				// Write domain to file
				if domainWriter != nil {
					mu.Lock()
					_, _ = domainWriter.WriteString(domain + "\n")
					if atomic.LoadInt64(&scannedCount)%1000 == 0 {
						_ = domainWriter.Flush()
					}
					mu.Unlock()
				}

				// Fetch subdomains and push non-blocking
				subs := fetchSubdomains(domain, httpClient, &subCount)
				if len(subs) > 0 {
					for _, sd := range subs {
						if seen.LoadOrStore(sd) {
							continue
						}
						select {
						case tasks <- sd:
						default:
							// drop to avoid OOM
						}
					}
				}

				// Check vulnerabilities
				for _, check := range checks {
					if url := tryGetURLWithClient(domain, check, httpClient); url != "" {
						atomic.AddInt64(counts[check.Path], 1)
						if w, ok := writers[check.Path]; ok {
							mu.Lock()
							_, _ = w.WriteString(url + "\n")
							_ = w.Flush()
							mu.Unlock()
						}
					}
				}

				atomic.AddInt64(&scannedCount, 1)
				if atomic.LoadInt64(&scannedCount)%10000 == 0 {
					runtime.GC()
				}
			}
		}()
	}

	// Progression : unique ligne, mise à jour continue
	go func() {
		for {
			totalVulns := 0
			for _, check := range checks {
				totalVulns += int(atomic.LoadInt64(counts[check.Path]))
			}
			fmt.Printf(
				"\r🔍 Scanné: %d | 🛡️ Vulnérables: %d | 🌐 Sous-domaines: %d | Queue: %d/%d",
				atomic.LoadInt64(&scannedCount),
				totalVulns,
				atomic.LoadInt64(&subCount),
				len(tasks),
				cap(tasks),
			)
			time.Sleep(1 * time.Second)
		}
	}()

	// CertStream silencieux (reconnexion automatique)
	go func() {
		for {
			conn, _, err := websocket.DefaultDialer.Dial("wss://certstream.calidog.io/", nil)
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					conn.Close()
					break
				}
				var data map[string]interface{}
				if json.Unmarshal(msg, &data) != nil || data["message_type"] != "certificate_update" {
					continue
				}
				d, ok := data["data"].(map[string]interface{})
				if !ok {
					continue
				}
				leaf, ok := d["leaf_cert"].(map[string]interface{})
				if !ok {
					continue
				}
				domains, ok := leaf["all_domains"].([]interface{})
				if !ok {
					continue
				}
				for _, dd := range domains {
					if domain, ok := dd.(string); ok {
						if seen.LoadOrStore(domain) {
							continue
						}
						select {
						case tasks <- domain:
						default:
							// drop if queue full
						}
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// Signal shutdown propre
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		close(tasks)
		wg.Wait()
		mu.Lock()
		for _, w := range writers {
			_ = w.Flush()
		}
		if domainWriter != nil {
			_ = domainWriter.Flush()
		}
		for _, f := range filesOut {
			_ = f.Close()
		}
		if domainFile != nil {
			_ = domainFile.Close()
		}
		mu.Unlock()
		fmt.Println("\nArrêt propre effectué.")
		os.Exit(0)
	}()

	// Seed initial (remplace ou supprime si inutile)
	seed := []string{"example.com"}
	for _, d := range seed {
		if !seen.LoadOrStore(d) {
			select {
			case tasks <- d:
			default:
			}
		}
	}

	// Bloque indéfiniment, progression s'affiche seule
	select {}
}

