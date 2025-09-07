### **🩸 EyeOfBlood - Professional Vulnerability Scanner**
EyeOfBlood is a professional scanner for automatically detecting vulnerabilities in network infrastructure. Use for one attack host. No to all device in network.

### **🚀Quick start**
- **Required**: Installed Go 1.21+ on your computer
- Download Go: https://golang.org/dl/
```
git clone https://github.com/whitegertsok/EyeOfBlood.git
cd EyeOfBlood
go mod init eyeofblood
go get github.com/fatih/color
go mod tidy
go build -o eyeofblood.exe
.\eyeofblood.exe -target example.com #(no to use https/http//:example.com/, only use domain)
.\eyeofblood.exe -target 192.168.1.1 -timeout 10
.\eyeofblood.exe -help
```
### **👇Key features👇**
**Scanning:**
1. Detect open ports (24 main ports)
2. Automatically detect services and versions
3. Analyze service banners and metadata

**Detection:**
1. Check for critical vulnerabilities (CVE)
2. Analyze software versions for known vulnerabilities
3. Intelligent correlation of ports and services

**Reporting:**
1. Generate detailed reports in Markdown
2. Real-time color output of results
3. Roadmap for attacks and recommendations for protection

### **🔍Threat Stack**
1. EternalBlue (SMB)
2. BlueKeep (RDP)
3. Heartbleed (OpenSSL)
4. ProxyShell (Exchange)
5. Zerologon (Netlogon)

```Reduce manual work and time to find a hacking target,``` **by @whitegertsok.**

