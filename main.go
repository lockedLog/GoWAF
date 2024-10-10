package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
)

func getSettings() int {
	var optionChoice int
	choices := []int{1, 2, 3, 4}

	for {
		fmt.Print("Check for WAF using:\n\n1. Generic XSS payload\n2. Generic SQL payload\n3. Both")
		fmt.Scan(&optionChoice)

		for _, choice := range choices {
			if optionChoice == choice {
				return optionChoice
			}
		}

		fmt.Println("Invalid choice, try again.")
	}
}

func filterFile() []string {
	filtered := []string{}

	fmt.Println("Filtering URLs...")
	input, err := os.Open("subs.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer input.Close()

	s := bufio.NewScanner(input)
	for s.Scan() {
		line := s.Text()
		if strings.Contains(line, "=") {
			trim := strings.SplitAfter(line, "=")
			trimmed := trim[0]
			fmt.Println("Valid URL:", Green+trimmed+Reset)

			filtered = append(filtered, trimmed)
		}
	}
	return filtered
}

func xss(urls []string) {
	const defaultPayload string = "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"

	for _, url := range urls {
		target := url + defaultPayload

		resp, err := http.Get(target)
		if err != nil {
			log.Printf("Failed to make xss request: %v", err)
			continue
		}
		defer resp.Body.Close()

		status := resp.StatusCode
		if status == 200 {
			fmt.Println(url, Yellow+"- not protected by WAF (XSS)."+Reset)
		} else if status == 403 {
			check, err := http.Get(url)
			if err != nil {
				continue
			}
			defer check.Body.Close()

			if check.StatusCode == 200 {
				fmt.Println(url, Red+"- protected by WAF (XSS)."+Reset)
			}
		}

	}
}

func sqli(urls []string) {
	for _, url := range urls {
		target := url + "'"

		resp, err := http.Get(target)
		if err != nil {
			log.Printf("Failed to make request: %v", err)
			continue
		}
		defer resp.Body.Close()
		status := resp.StatusCode

		if status == 500 {
			check, err := http.Get(url)
			if err != nil {
				log.Printf("Failed to make sqli request: %v", err)
				continue
			}
			defer check.Body.Close()

			if check.StatusCode == 200 {
				fmt.Println(url, Green+"- possibly vulnerable to SQLI"+Reset)
			}
		} else if status == 200 {
			fmt.Println(url, Yellow+"- not protected by WAF (SQLI)."+Reset)
		} else if status == 403 {
			check, err := http.Get(url)
			if err != nil {
				continue
			}
			defer check.Body.Close()

			if check.StatusCode == 200 {
				fmt.Println(url, Red+"- protected by WAF (SQLI)."+Reset)
			}
		}

	}
}

func main() {
	urls := filterFile()
	settings := getSettings()
	if settings == 1 {
		xss(urls)
	} else if settings == 2 {
		sqli(urls)
	} else {
		xss(urls)
		sqli(urls)
	}
}
