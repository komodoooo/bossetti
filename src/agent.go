package main

import (
	"os"
	"fmt"
	"log"
	"github.com/fsnotify/fsnotify"
	vt "github.com/VirusTotal/vt-go"
)

func main() {
	client := vt.NewClient(APIKEY)
	watcher, err := fsnotify.NewWatcher()
    	if err != nil { log.Fatal(err) }
    	defer watcher.Close()
	err = watcher.Add(os.Getenv("USERPROFILE")+"\\Downloads")
    	if err != nil { log.Fatal(err) }
		for {
        	select {
        	case event := <-watcher.Events:
            		if event.Op&fsnotify.Create == fsnotify.Create {
				send_notification("Uploading", event.Name, "")
				obj, err := UploadFile(event.Name, client)
				send_notification("Scanning", "Wait a bit", obj.ID())
				if err != nil { log.Fatalf("Error: %v", err) }
				stats, n, err := GetAnalysisAttributes(obj, client)
				if err != nil { log.Fatalf("Error: %v", err) }
				if stats[0] + stats[1] == 0 {
					send_notification("File is secure!", "", obj.ID())
				} else {
					send_notification("File could be dangerous", fmt.Sprintf("Flagged as Malicios (%d), Suspicious (%d)\nby %d antiviruses", stats[1], stats[0], n), obj.ID())
				}
            		}
        	case err := <-watcher.Errors:
            		log.Println("Error: ", err)
        	}
    	}
}
