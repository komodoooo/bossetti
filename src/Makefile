APIKEY ?= ""
ifeq ($(OS), Windows_NT)
	SHELL=C:\Windows\System32\cmd.exe
	BOSSETTI_BINARY := bossetti.exe
	AGENT_BINARY := bagent.exe
endif
build: bossetti.go agent.go main.go
	go mod init vt-go
	go get github.com/VirusTotal/vt-go
	go get github.com/fsnotify/fsnotify
	go get github.com/go-toast/toast
	go build -ldflags="-H=windowsgui -X 'main.APIKEY=$(APIKEY)'" -o $(BOSSETTI_BINARY) main.go bossetti.go
	go build -ldflags="-H=windowsgui -X 'main.APIKEY=$(APIKEY)'" -o $(AGENT_BINARY) agent.go bossetti.go
install: bossetti.exe bagent.exe
	copy "$(AGENT_BINARY)" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\$(AGENT_BINARY)"
	copy "$(BOSSETTI_BINARY)" "%APPDATA%\$(BOSSETTI_BINARY)"
clean:
	del /Q go.mod go.sum bossetti.exe bagent.exe
