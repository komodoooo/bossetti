package main

import (
	"os"
	"fmt"
	"log"
	"time"
	"encoding/json"
	vt "github.com/VirusTotal/vt-go"
)

const APIKEY = "YOUR_VT_APIKEY"

func main() {
	if len(os.Args)<2{ log.Fatal("Must specify a file") }
	for i:=1; i<len(os.Args); i++ {
		filepath := os.Args[i]
		client := vt.NewClient(APIKEY)
		file, err := os.Open(filepath)
		if err != nil { log.Fatal("Invalid filepath.") }
		defer file.Close()
		object, err := client.NewFileScanner().ScanFile(file, nil)
		if err != nil { log.Fatalf("Error: %v", err) }
		fmt.Printf("\n\"%s\" successfully uploaded to the following URL:\nhttps://www.virustotal.com/gui/file-analysis/%s\n", filepath, object.ID())
		var harmless, suspicious, malicious, undetected float64
		var ntotalav int
		for {
			var result map[string]interface{}
			url := vt.URL("analyses/%s", object.ID())
			_, err = client.GetData(url, &result)
			if err != nil { log.Fatalf("Error: %v", err) }
			attributes := result["attributes"].(map[string]interface{})["stats"].(map[string]interface{})
			harmless, _ = attributes["harmless"].(json.Number).Float64()
			suspicious, _ = attributes["suspicious"].(json.Number).Float64()
			malicious, _ = attributes["malicious"].(json.Number).Float64()
			undetected, _ = attributes["undetected"].(json.Number).Float64()
			ntotalav = int(malicious)+int(undetected)
			if ntotalav != 0 { break }
			fmt.Print(".")
			time.Sleep(1*time.Second) 
		}
		fmt.Printf("\nOn %d antiviruses file was flagged as:\n  Harmless (%d)\n  Suspicious (%d)\n  Malicious (%d)\n\n", ntotalav, int(harmless), int(suspicious), int(malicious))
	}
}
