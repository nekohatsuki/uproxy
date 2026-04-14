package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/nekohatsuki/uproxy/proxy"
)

func main() {
	// 1. Get a dialer. You can easily switch between HTTP or SOCKS5.
	// You can test auth as well: "http://user:pass@proxy-server:8080"
	d, err := proxy.FromURL("http://127.0.0.1:8080", nil)
	if err != nil {
		log.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// 2. Plug it directly into the HTTP client via DialContext
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
		},
	}

	// 3. Use it to perform requests (HTTPS will now work perfectly through HTTP proxies)
	resp, err := httpClient.Get("https://bing.com")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body: %s...\n", string(body[:100])) // Just printing first 100 bytes
}
