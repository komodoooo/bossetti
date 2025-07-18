package main

import (
	"os"
	"fmt"
	vt "github.com/VirusTotal/vt-go"
)

func main() {
	client := vt.NewClient(APIKEY)
	filepath := os.Args[1]
	send_notification("Uploading", filepath, "")
	object, err := UploadFile(filepath, client)
	if err != nil { 
		send_notification("Error", err.Error(), object.ID())
		return
	}
	send_notification("Scanning", filepath, object.ID())
	stats, n, err := GetAnalysisAttributes(object, client)
	if err != nil { 
		send_notification("Error", err.Error(), object.ID())
		return
	}
	if stats[0]+stats[1] == 0 {
		send_notification("File is secure!", "", object.ID())
	} else {
		send_notification("Done", fmt.Sprintf("Flagged as Malicious (%d), Suspicious (%d)\nby %d antiviruses", stats[1], stats[0], n), object.ID())
	}
}
