package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
)

type APIResponse struct {
	Result struct {
		CVEItems []struct {
			CVE struct {
				DataMeta struct {
					ID string `json:"ID"`
				} `json:"CVE_data_meta"`
				Description struct {
					DescriptionData []struct {
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
			} `json:"cve"`
			Impact struct {
				BaseMetricV3 struct {
					CVSSV3 struct {
						BaseScore        float64 `json:"baseScore"`
						BaseSeverity     string  `json:"baseSeverity"`
						AttackVector     string  `json:"attackVector"`
						AttackComplexity string  `json:"attackComplexity"`
						VectorString     string  `json:"vectorString"`
					} `json:"cvssV3"`
				} `json:"baseMetricV3"`
			} `json:"impact"`
			PublishedDate string `json:"publishedDate"`
		} `json:"CVE_Items"`
	} `json:"result"`
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <CVE-ID> [-v]\n", os.Args[0])
		flag.PrintDefaults()
	}

	verbose := flag.Bool("v", false, "Print raw JSON response in verbose mode")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	cveID := args[0]

	// Prepend "CVE-" prefix if missing
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cve/1.0/%s", cveID)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch data: %s", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	// Print raw JSON in verbose mode
	if *verbose {
		fmt.Println("Raw JSON Response:", string(body))
	}

	var response APIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Fatalf("Failed to unmarshal data: %s", err)
	}

	if len(response.Result.CVEItems) == 0 {
		log.Fatalf("No CVE data found for the given ID.")
	}

	cveItem := response.Result.CVEItems[0]

	// Display the metadata in a table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "Field\tValue")
	fmt.Fprintln(w, "-----\t-----")
	fmt.Fprintf(w, "CVE ID\t%s\n", cveItem.CVE.DataMeta.ID)
	fmt.Fprintf(w, "Description\t%s\n", cveItem.CVE.Description.DescriptionData[0].Value)
	fmt.Fprintf(w, "Published Date\t%s\n", cveItem.PublishedDate)
	fmt.Fprintf(w, "Base Score\t%f\n", cveItem.Impact.BaseMetricV3.CVSSV3.BaseScore)
	fmt.Fprintf(w, "Severity\t%s\n", cveItem.Impact.BaseMetricV3.CVSSV3.BaseSeverity)
	fmt.Fprintf(w, "Attack Vector\t%s\n", cveItem.Impact.BaseMetricV3.CVSSV3.AttackVector)
	fmt.Fprintf(w, "Attack Complexity\t%s\n", cveItem.Impact.BaseMetricV3.CVSSV3.AttackComplexity)
	fmt.Fprintf(w, "CVSS\t%s\n", cveItem.Impact.BaseMetricV3.CVSSV3.VectorString)
	w.Flush()
}

