package main

import (
	"os"
	"fmt"
	"slices"
	"github.com/fsnotify/fsnotify"
	vt "github.com/VirusTotal/vt-go"
)

func main() {
	client := vt.NewClient(APIKEY)
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()
	watcher.Add(os.Getenv("USERPROFILE")+"\\Downloads")
	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Create == fsnotify.Create {
				if len(event.Name)>=3 && slices.Contains(FILE_EXTENSIONS, event.Name[len(event.Name)-3:]){
					send_notification("Uploading", event.Name, "")
					obj, err := UploadFile(event.Name, client)
					if err != nil {
						send_notification("Error", err.Error(), obj.ID())
						continue
					}
					send_notification("Scanning", event.Name, obj.ID())
					stats, n, _ := GetAnalysisAttributes(obj, client)
					if stats[0] + stats[1] == 0 {
						send_notification("File is secure!", "", obj.ID())
					} else {
						send_notification("File could be dangerous", fmt.Sprintf("Flagged as Malicios (%d), Suspicious (%d)\nby %d antiviruses", stats[1], stats[0], n), obj.ID())
					}
				}
			}
		case err := <-watcher.Errors:
			send_notification("Error", err.Error(), "")
		}
	}
}
