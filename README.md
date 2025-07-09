# Bossetti
![image](https://github.com/user-attachments/assets/ed04148c-0ee3-4537-996f-3924f5bdd028)
<br>A golang utility for Windows that helps you check if a file is guilty through Virus Total API.<br>
Better than any antivirus because it's not bloated.

### Installation
Before all these steps make sure to [get your VirusTotal API key](https://www.virustotal.com/gui/my-apikey)
```
git clone https://github.com/komodoooo/bossetti
cd bossetti/src
make build APIKEY="YOUR_VT_APIKEY"
make install
make clean
```
Then you will need to open a cmd with privileges and add a registry system rule to insert a voice into the contextual menu, run the following.<br>
`reg add "HKEY_CLASSES_ROOT\*\shell\Scan with Bossetti\command" /ve /t REG_SZ /d "\"%APPDATA%\\bossetti.exe\" \"%1\"" /f`

Now reboot or start `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\bagent.exe` to run the agent and make changes effective.<br>
As it hints, Bossetti will run automatically every time you will turn on your PC
### Usage
* You can scan a single file with _**Right-click > "Scan with Bossetti"**_
* Bossetti will monitor and scan for new files in your `%USERPROFILE%\Downloads` directory, notifying you with details and a link to the web dashboard for additional data.
> The file extensions allowed to be uploaded during directory monitoring are listed [here](src/bossetti.go), feel free to change them before compiling

[**#FREEBOSSETTI**](https://it.wikipedia.org/wiki/Omicidio_di_Yara_Gambirasio)
