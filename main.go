package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {

	var domains []string

	var dates bool
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")

	var noSubs bool
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")

	var getVersionsFlag bool
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")

	flag.Parse()

	if flag.NArg() > 0 {
		// fetch for a single domain
		domains = []string{flag.Arg(0)}
	} else {

		// fetch for all domains from stdin
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}

		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	// get-versions mode
	if getVersionsFlag {

		for _, u := range domains {
			versions, err := getVersions(u)
			if err != nil {
				continue
			}
			fmt.Println(strings.Join(versions, "\n"))
		}

		return
	}

	for _, domain := range domains {

		var wg sync.WaitGroup
		wurls := make(chan wurl, 1000) // Buffered channel to prevent blocking
		seen := make(map[string]bool)
		var seenMutex sync.Mutex

		// Start goroutine to handle output
		outputDone := make(chan bool)
		go func() {
			for w := range wurls {
				seenMutex.Lock()
				if seen[w.url] {
					seenMutex.Unlock()
					continue
				}
				seen[w.url] = true
				seenMutex.Unlock()

				if dates && w.date != "" {
					d, err := time.Parse("20060102150405", w.date)
					if err != nil {
						fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.date, w.url)
						fmt.Println(w.url)
					} else {
						fmt.Printf("%s %s\n", d.Format(time.RFC3339), w.url)
					}
				} else {
					fmt.Println(w.url)
				}
			}
			outputDone <- true
		}()

		// Start fetch functions
		wg.Add(1)
		go func() {
			defer wg.Done()
			getWaybackURLsStreaming(domain, noSubs, wurls)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := getCommonCrawlURLs(domain, noSubs)
			if err != nil {
				return
			}
			for _, r := range resp {
				if noSubs && isSubdomain(r.url, domain) {
					continue
				}
				wurls <- r
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := getVirusTotalURLs(domain, noSubs)
			if err != nil {
				return
			}
			for _, r := range resp {
				if noSubs && isSubdomain(r.url, domain) {
					continue
				}
				wurls <- r
			}
		}()

		// Wait for all fetchers to complete, then close channel
		go func() {
			wg.Wait()
			close(wurls)
		}()

		// Wait for output to complete
		<-outputDone
	}
}

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool) ([]wurl, error)

// New streaming version of getWaybackURLs
func getWaybackURLsStreaming(domain string, noSubs bool, output chan<- wurl) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=plain&collapse=urlkey", subsWildcard, domain),
	)
	if err != nil {
		return
	}
	defer res.Body.Close()

	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}

		// Plain format: urlkey timestamp original mimetype statuscode digest length
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			w := wurl{date: fields[1], url: fields[2]}
			
			// Check subdomain filter here to avoid sending unnecessary data
			if noSubs && isSubdomain(w.url, domain) {
				continue
			}
			
			select {
			case output <- w:
			default:
				// Channel is full, skip this URL to prevent blocking
			}
		}
	}
}

func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain),
	)
	if err != nil {
		return []wurl{}, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]wurl, 0)

	for sc.Scan() {

		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

		if err != nil {
			continue
		}

		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
	}

	return out, nil

}

func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		// no API key isn't an error,
		// just don't fetch
		return out, nil
	}

	fetchURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey,
		domain,
	)

	resp, err := http.Get(fetchURL)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
			// TODO: handle VT date format (2018-03-26 09:22:43)
			//Date string `json:"scan_date"`
		} `json:"detected_urls"`
	}{}

	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&wrapper)

	for _, u := range wrapper.URLs {
		out = append(out, wurl{url: u.URL})
	}

	return out, nil

}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		// we can't parse the URL so just
		// err on the side of including it in output
		return false
	}

	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	out := make([]string, 0)

	resp, err := http.Get(fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s&output=json", u,
	))

	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	r := [][]string{}

	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&r)
	if err != nil {
		return out, err
	}

	first := true
	seen := make(map[string]bool)
	for _, s := range r {

		// skip the first element, it's the field names
		if first {
			first = false
			continue
		}

		// fields: "urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}

	return out, nil
}