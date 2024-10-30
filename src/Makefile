ifeq ($(OS), Windows_NT)
	SHELL=C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
    BOSSETTI_BINARY := bossetti.exe
    AGENT_BINARY := bagent.exe
endif
compile: bossetti.go agent.go main.go
	go mod init vt-go
	go get github.com/VirusTotal/vt-go
	go get github.com/fsnotify/fsnotify
	go get github.com/go-toast/toast
	go build -o $(BOSSETTI_BINARY) main.go bossetti.go
	go build -ldflags -H=windowsgui -o $(AGENT_BINARY) agent.go bossetti.go
setup:
	cmd /C copy "$(AGENT_BINARY)" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\$(AGENT_BINARY)"
	cmd /C copy "$(BOSSETTI_BINARY)" "%APPDATA%\$(BOSSETTI_BINARY)"
	cmd /C powershell -C Start-Process -FilePath 'reg.bat' -Verb RunAs
clean:
	cmd /C del /Q go.mod go.sum
