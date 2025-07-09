package main

import (
	"os"
	"fmt"
	"time"
	"encoding/json"
	"github.com/go-toast/toast"
	vt "github.com/VirusTotal/vt-go"
)

var APIKEY string
var FILE_EXTENSIONS = []string{"exe", "com", "bat", "cmd", "ps1", "vbs", "msi", "wsf", "zip", "rar", "7z"}

func UploadFile(filepath string, client *vt.Client)(*vt.Object, error){
	file, err := os.Open(filepath)
	if err != nil { return nil, fmt.Errorf("Invalid filepath") }
	defer file.Close()
	object, err := client.NewFileScanner().ScanFile(file, nil)
	if err != nil { return nil, err }
	return object, nil
}

func GetAnalysisAttributes(object *vt.Object, client *vt.Client)([2]int, int, error){
	var ntotalav int
	var suspicious, malicious, undetected float64
	for {
		var result map[string]interface{}
		url := vt.URL("analyses/%s", object.ID())
		_, err := client.GetData(url, &result)
		if err != nil { return [2]int{}, 0, err }
		attributes := result["attributes"].(map[string]interface{})["stats"].(map[string]interface{})
		suspicious, _ = attributes["suspicious"].(json.Number).Float64()
		malicious, _ = attributes["malicious"].(json.Number).Float64()
		undetected, _ = attributes["undetected"].(json.Number).Float64()
		ntotalav = int(malicious)+int(undetected)
		if ntotalav != 0 { break }
		fmt.Print(".")
		time.Sleep(1*time.Second) 
	}
	return [2]int{int(suspicious), int(malicious)}, ntotalav, nil
}

func send_notification(title string, text string, url string){
	notification := toast.Notification{
        	AppID: "Bossetti", 
        	Title: title,
        	Message: text,
    	}
	if url != "" {
		notification.Actions = []toast.Action{
			{"protocol", "See analysis", "https://www.virustotal.com/gui/file-analysis/"+url},
		}
	}
	notification.Push()
}
