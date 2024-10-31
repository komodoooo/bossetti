package main

import (
	"os"
	"fmt"
	"log"
	vt "github.com/VirusTotal/vt-go"
)

func main() {
	if len(os.Args)<2{ log.Fatal("Must specify a file") }
	client := vt.NewClient(APIKEY)
	filepath := os.Args[0]					//contextual menu pass filepath with arg 0, not 1
	send_notification("Uploading", filepath, "")
	object, err := UploadFile(filepath, client)
	if err != nil { log.Fatalf("Error: %v", err) }
	send_notification("Scanning", "Wait a bit", object.ID())
	stats, n, err := GetAnalysisAttributes(object, client)
	if err != nil { log.Fatalf("Error: %v", err) }
	if stats[0]+stats[1] == 0 {
		send_notification("File is secure!", "", object.ID())
	} else {
		send_notification("Done", fmt.Sprintf("Flagged as Malicios (%d), Suspicious (%d)\nby %d antiviruses", stats[1], stats[0], n), object.ID())
	}
}
