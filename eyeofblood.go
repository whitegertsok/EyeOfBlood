package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Уязвимость представляет известную уязвимость
type Vulnerability struct {
	CVE          string   `json:"cve"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	Ports        []int    `json:"ports"`
	Services     []string `json:"services"`
	Versions     []string `json:"versions,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Exploit      string   `json:"exploit,omitempty"`
	Solution     string   `json:"solution,omitempty"`
}

// Результат сканирования содержит информацию о найденном сервисе
type ScanResult struct {
	Port    int
	Service string
	Version string
	Banner  string
	Vulns   []Vulnerability
	Error   string
}

// Цвета для вывода в консоль
var (
	cyan    = color.New(color.FgCyan)
	red     = color.New(color.FgRed)
	green   = color.New(color.FgGreen)
	yellow  = color.New(color.FgYellow)
	magenta = color.New(color.FgMagenta)
	blue    = color.New(color.FgBlue)
)

// База данных уязвимостей
var vulnerabilityDB = []Vulnerability{
	{
		CVE:          "CVE-2017-0143",
		Description:  "EternalBlue - Удаленное выполнение кода через SMB",
		Severity:     "КРИТИЧЕСКИЙ",
		Ports:        []int{445},
		Services:     []string{"smb", "microsoft-ds"},
		Versions:     []string{"windows 7", "windows 8.1", "windows server 2008", "windows server 2012"},
		FixedVersion: "MS17-010",
		Exploit:      "use exploit/windows/smb/ms17_010_eternalblue",
		Solution:     "Установить обновление безопасности MS17-010",
	},
	{
		CVE:          "CVE-2019-0708",
		Description:  "BlueKeep - Удаленное выполнение кода через RDP",
		Severity:     "КРИТИЧЕСКИЙ",
		Ports:        []int{3389},
		Services:     []string{"rdp", "ms-wbt-server"},
		Versions:     []string{"windows 7", "windows server 2008", "windows server 2008 r2"},
		FixedVersion: "KB4499175, KB4500331",
		Exploit:      "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
		Solution:     "Установить обновления для Windows May 2019",
	},
	{
		CVE:          "CVE-2014-0160",
		Description:  "Heartbleed - Утечка информации через OpenSSL",
		Severity:     "ВЫСОКИЙ",
		Ports:        []int{443, 8443, 993, 995},
		Services:     []string{"ssl", "https", "imaps", "pop3s"},
		Versions:     []string{"openssl 1.0.1", "openssl 1.0.1a", "openssl 1.0.1b", "openssl 1.0.1c", "openssl 1.0.1d", "openssl 1.0.1e", "openssl 1.0.1f"},
		FixedVersion: "1.0.1g",
		Exploit:      "use auxiliary/scanner/ssl/openssl_heartbleed",
		Solution:     "Обновить OpenSSL до версии 1.0.1g или выше",
	},
	{
		CVE:          "CVE-2021-34473",
		Description:  "ProxyShell - Удаленное выполнение кода в Microsoft Exchange",
		Severity:     "КРИТИЧЕСКИЙ",
		Ports:        []int{443, 8443},
		Services:     []string{"http", "https", "microsoft-httpapi", "microsoft exchange"},
		Versions:     []string{"exchange server 2013", "exchange server 2016", "exchange server 2019"},
		FixedVersion: "KB5004778",
		Exploit:      "use exploit/linux/http/microsoft_exchange_proxyshell_rce",
		Solution:     "Установить последние обновления Exchange July 2021",
	},
	{
		CVE:          "CVE-2020-1472",
		Description:  "Zerologon - Подмена учетных данных Netlogon",
		Severity:     "КРИТИЧЕСКИЙ",
		Ports:        []int{445},
		Services:     []string{"smb", "microsoft-ds"},
		Versions:     []string{"windows server 2016", "windows server 2019", "windows server 2012", "windows server 2012 r2"},
		FixedVersion: "KB4557222, KB4571692",
		Exploit:      "use auxiliary/admin/dcerpc/cve_2020_1472_zerologon",
		Solution:     "Установить обновления Windows October 2020",
	},
}

func main() {
	// Парсим аргументы командной строки
	targetPtr := flag.String("target", "", "Target to scan (IP address or domain name)")
	timeoutPtr := flag.Int("timeout", 5, "Connection timeout in seconds")
	helpPtr := flag.Bool("help", false, "Show help information")
	flag.Parse()

	// Show help if requested
	if *helpPtr {
		printHelp()
		os.Exit(0)
	}

	if *targetPtr == "" {
		fmt.Printf("Usage: %s -target <IP or domain> [-timeout <seconds>]\n", os.Args[0])
		fmt.Printf("Example: %s -target 192.168.1.100\n", os.Args[0])
		fmt.Printf("Example: %s -target example.com -timeout 10\n", os.Args[0])
		fmt.Printf("Use %s -help for more information\n", os.Args[0])
		os.Exit(1)
	}

	target := *targetPtr
	timeout := time.Duration(*timeoutPtr) * time.Second

	fmt.Println(cyan.Sprint(`
___________            ________   _______________.__                    .___
\_   _____/__.__. ____ \_____  \_/ ____\______   \  |   ____   ____   __| _/
 |    __)<   |  |/ __ \ /   |   \   __\ |    |  _/  |  /  _ \ /  _ \ / __ | 
 |        \___  \  ___//    |    \  |   |    |   \  |_(  <_> |  <_> ) /_/ | 
/_______  / ____|\___  >_______  /__|   |______  /____/\____/ \____/\____ | 
        \/\/         \/        \/              \/                        \/ 
	`))
	fmt.Println(cyan.Sprint("          EyeOfBlood - Professional Vulnerability Scanner"))
	fmt.Println(cyan.Sprint("                  Version 2.2 - For Commercial Use\n"))

	fmt.Printf("%s Scanning target: %s\n", cyan.Sprint("[*]"), target)
	fmt.Printf("%s Timeout: %d seconds\n", cyan.Sprint("[*]"), *timeoutPtr)
	fmt.Printf("%s Scan started: %s\n\n", cyan.Sprint("[*]"), time.Now().Format("15:04:05"))

	// Фаза 1: Быстрое сканирование портов
	openPorts := quickPortScan(target, timeout)
	if len(openPorts) == 0 {
		fmt.Printf("%s No open ports found\n", red.Sprint("[-]"))
		os.Exit(0)
	}

	fmt.Printf("%s Found %d open ports: %v\n", green.Sprint("[+]"), len(openPorts), openPorts)

	// Фаза 2: Определение сервисов и проверка уязвимостей
	results := make(chan ScanResult, len(openPorts))
	var wg sync.WaitGroup

	fmt.Printf("%s Analyzing services...\n", cyan.Sprint("[*]"))
	for _, port := range openPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			result := analyzeService(target, p, timeout)
			if result.Port != 0 {
				results <- result
			}
		}(port)
	}

	wg.Wait()
	close(results)

	// Сбор и вывод результатов
	var allResults []ScanResult
	for result := range results {
		allResults = append(allResults, result)
	}

	totalVulns, criticalVulns := countVulns(allResults)
	printResults(allResults, totalVulns, criticalVulns)
	generateReport(target, allResults, totalVulns, criticalVulns)

	fmt.Printf("%s Scan completed: %s\n", green.Sprint("[+]"), time.Now().Format("15:04:05"))
}

func printHelp() {
	fmt.Println(cyan.Sprint(`
___________            ________   _______________.__                    .___
\_   _____/__.__. ____ \_____  \_/ ____\______   \  |   ____   ____   __| _/
 |    __)<   |  |/ __ \ /   |   \   __\ |    |  _/  |  /  _ \ /  _ \ / __ | 
 |        \___  \  ___//    |    \  |   |    |   \  |_(  <_> |  <_> ) /_/ | 
/_______  / ____|\___  >_______  /__|   |______  /____/\____/ \____/\____ | 
        \/\/         \/        \/              \/                        \/              
	`))
	fmt.Println(cyan.Sprint("          EyeOfBlood - Professional Vulnerability Scanner"))
	fmt.Println(cyan.Sprint("                  Version 2.2 - For Commercial Use\n"))

	fmt.Println("DESCRIPTION:")
	fmt.Println("  EyeOfBlood is a professional security scanner designed for penetration testers")
	fmt.Println("  and security professionals. It identifies open ports, services, and known")
	fmt.Println("  vulnerabilities in target systems.\n")

	fmt.Println("USAGE:")
	fmt.Printf("  %s -target <TARGET> [OPTIONS]\n", os.Args[0])
	fmt.Println()

	fmt.Println("OPTIONS:")
	fmt.Println("  -target string")
	fmt.Println("        Target to scan (IP address or domain name) (required)")
	fmt.Println()
	fmt.Println("  -timeout int")
	fmt.Println("        Connection timeout in seconds (default: 5)")
	fmt.Println()
	fmt.Println("  -help")
	fmt.Println("        Show this help message")
	fmt.Println()

	fmt.Println("EXAMPLES:")
	fmt.Printf("  %s -target 192.168.1.100\n", os.Args[0])
	fmt.Printf("  %s -target example.com -timeout 10\n", os.Args[0])
	fmt.Printf("  %s -target 10.0.0.1 -timeout 3\n", os.Args[0])
	fmt.Println()

	fmt.Println("FEATURES:")
	fmt.Println("  • Fast parallel port scanning")
	fmt.Println("  • Service detection and banner grabbing")
	fmt.Println("  • Vulnerability assessment")
	fmt.Println("  • Detailed HTML report generation")
	fmt.Println("  • Color-coded output")
	fmt.Println("  • Commercial-grade performance")
	fmt.Println()

	fmt.Println("SUPPORTED VULNERABILITIES:")
	fmt.Println("  • CVE-2017-0143 (EternalBlue) - Critical SMB vulnerability")
	fmt.Println("  • CVE-2019-0708 (BlueKeep) - Critical RDP vulnerability")
	fmt.Println("  • CVE-2014-0160 (Heartbleed) - OpenSSL information disclosure")
	fmt.Println("  • CVE-2021-34473 (ProxyShell) - Microsoft Exchange RCE")
	fmt.Println("  • CVE-2020-1472 (Zerologon) - Netlogon privilege escalation")
	fmt.Println()

	fmt.Println("SCANNED PORTS:")
	fmt.Println("  21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP),")
	fmt.Println("  110 (POP3), 135 (RPC), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS),")
	fmt.Println("  445 (SMB), 993 (IMAPS), 995 (POP3S), 1433 (MSSQL), 3306 (MySQL),")
	fmt.Println("  3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 6379 (Redis),")
	fmt.Println("  27017 (MongoDB), 8080 (HTTP-Alt), 8443 (HTTPS-Alt), 9000 (Various)")
	fmt.Println()

	fmt.Println("REPORTING:")
	fmt.Println("  Scanner generates detailed Markdown reports with:")
	fmt.Println("  • Executive summary")
	fmt.Println("  • Technical findings")
	fmt.Println("  • Attack roadmap")
	fmt.Println("  • Security recommendations")
	fmt.Println()

	fmt.Println("NOTE:")
	fmt.Println("  This tool is intended for authorized security testing only.")
	fmt.Println("  Always obtain proper permission before scanning any systems.")
}

// Остальной код остается без изменений...
func quickPortScan(target string, timeout time.Duration) []int {
	var openPorts []int
	fmt.Printf("%s Scanning common ports...\n", cyan.Sprint("[*]"))

	// Основные порты для проверки
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
		993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 27017, 8080, 8443, 9000}

	results := make(chan int, len(commonPorts))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Ограничиваем количество одновременных соединений

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(p)), timeout)
			if err == nil {
				results <- p
				conn.Close()
			}
		}(port)
	}

	wg.Wait()
	close(results)

	for port := range results {
		openPorts = append(openPorts, port)
		fmt.Printf("%s Port %d open\n", green.Sprint("[+]"), port)
	}

	return openPorts
}

func analyzeService(target string, port int, timeout time.Duration) ScanResult {
	result := ScanResult{Port: port}

	// Пытаемся получить баннер
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), timeout)
	if err != nil {
		result.Error = fmt.Sprintf("Connection error: %v", err)
		return result
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Отправляем специфичные для протокола запросы
	switch port {
	case 21:
		fmt.Fprintf(conn, "USER anonymous\r\n")
	case 22:
		// SSH баннер приходит автоматически
	case 25:
		fmt.Fprintf(conn, "EHLO example.com\r\n")
	case 80, 443, 8080, 8443:
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: EyeOfBlood/2.2\r\n\r\n", target)
	case 445:
		// SMB будет обработан через определение версии
	}

	// Читаем полный баннер
	fullBanner, bannerErr := readFullBanner(conn, timeout)
	if bannerErr != nil {
		result.Error = fmt.Sprintf("Banner read error: %v", bannerErr)
	} else {
		result.Banner = strings.TrimSpace(fullBanner)
	}

	// Определяем сервис на основе порта и баннера
	result.Service = detectService(port, result.Banner)
	result.Version = extractVersion(result.Banner)
	result.Vulns = checkVulnerabilities(port, result.Service, result.Version, result.Banner)

	return result
}

func readFullBanner(conn net.Conn, timeout time.Duration) (string, error) {
	var fullBanner bytes.Buffer
	reader := bufio.NewReader(conn)

	// Устанавливаем таймаут для чтения
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Читаем все доступные данные
	buffer := make([]byte, 1024)
	for {
		n, err := reader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fullBanner.String(), err
		}
		if n == 0 {
			break
		}
		fullBanner.Write(buffer[:n])

	}

	return fullBanner.String(), nil
}

func detectService(port int, banner string) string {
	bannerLower := strings.ToLower(banner)

	// Сначала пытаемся определить по баннеру
	if strings.Contains(bannerLower, "ssh") {
		return "SSH"
	} else if strings.Contains(bannerLower, "ftp") {
		return "FTP"
	} else if strings.Contains(bannerLower, "smtp") {
		return "SMTP"
	} else if strings.Contains(bannerLower, "http") {
		if strings.Contains(bannerLower, "apache") {
			return "HTTP (Apache)"
		} else if strings.Contains(bannerLower, "nginx") {
			return "HTTP (Nginx)"
		} else if strings.Contains(bannerLower, "iis") {
			return "HTTP (IIS)"
		} else if strings.Contains(bannerLower, "tomcat") {
			return "HTTP (Tomcat)"
		}
		return "HTTP/HTTPS"
	} else if strings.Contains(bannerLower, "redis") {
		return "Redis"
	} else if strings.Contains(bannerLower, "microsoft-ds") || strings.Contains(bannerLower, "smb") {
		return "SMB"
	} else if strings.Contains(bannerLower, "rdp") || strings.Contains(bannerLower, "ms-wbt-server") {
		return "RDP"
	} else if strings.Contains(bannerLower, "mssql") {
		return "MSSQL"
	} else if strings.Contains(bannerLower, "mysql") {
		return "MySQL"
	} else if strings.Contains(bannerLower, "postgresql") {
		return "PostgreSQL"
	} else if strings.Contains(bannerLower, "mongodb") {
		return "MongoDB"
	}

	// Если по баннеру не определили, используем порт по умолчанию
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 443, 8080, 8443:
		return "HTTP/HTTPS"
	case 445:
		return "SMB"
	case 3389:
		return "RDP"
	case 6379:
		return "Redis"
	case 1433:
		return "MSSQL"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 27017:
		return "MongoDB"
	}

	return "Unknown"
}

func extractVersion(banner string) string {
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`([0-9]+\.[0-9]+)`),
		regexp.MustCompile(`([0-9]+)`),
	}

	for _, pattern := range versionPatterns {
		if match := pattern.FindString(banner); match != "" {
			return match
		}
	}
	return "Unknown"
}

func checkVulnerabilities(port int, service, version, banner string) []Vulnerability {
	var foundVulns []Vulnerability
	serviceLower := strings.ToLower(service)
	bannerLower := strings.ToLower(banner)

	for _, vuln := range vulnerabilityDB {
		// Проверяем совпадение портов
		portMatch := false
		for _, p := range vuln.Ports {
			if p == port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			continue
		}

		// Проверяем совпадение сервисов
		serviceMatch := false
		for _, s := range vuln.Services {
			if strings.Contains(serviceLower, strings.ToLower(s)) ||
				strings.Contains(bannerLower, strings.ToLower(s)) {
				serviceMatch = true
				break
			}
		}
		if !serviceMatch {
			continue
		}

		// Если версия неизвестна, пропускаем проверку - не можем подтвердить уязвимость
		if version == "Unknown" {
			continue
		}

		// Проверяем совпадение версий
		versionMatch := false
		for _, affectedVersion := range vuln.Versions {
			if strings.Contains(strings.ToLower(version), strings.ToLower(affectedVersion)) ||
				strings.Contains(strings.ToLower(banner), strings.ToLower(affectedVersion)) {
				versionMatch = true
				break
			}
		}

		if versionMatch {
			// Дополнительная проверка: если версия исправлена, не показываем уязвимость
			if vuln.FixedVersion != "" {
				if compareVersions(version, vuln.FixedVersion) >= 0 {
					continue // Версия исправлена, пропускаем
				}
			}
			foundVulns = append(foundVulns, vuln)
		}
	}

	return foundVulns
}

func compareVersions(v1, v2 string) int {
	// Простая реализация сравнения версий
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		num1, _ := strconv.Atoi(parts1[i])
		num2, _ := strconv.Atoi(parts2[i])

		if num1 < num2 {
			return -1
		}
		if num1 > num2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}

func countVulns(results []ScanResult) (total, critical int) {
	for _, result := range results {
		total += len(result.Vulns)
		for _, vuln := range result.Vulns {
			if vuln.Severity == "КРИТИЧЕСКИЙ" {
				critical++
			}
		}
	}
	return total, critical
}

func printResults(results []ScanResult, totalVulns, criticalVulns int) {
	fmt.Printf("\n%s %s\n", magenta.Sprint("[=== SCAN RESULTS ===]"), "")

	for _, result := range results {
		fmt.Printf("%s Port %d: %s", green.Sprint("[+]"), result.Port, result.Service)
		if result.Version != "Unknown" {
			fmt.Printf(" (version: %s)", result.Version)
		}
		fmt.Println()

		if result.Error != "" {
			fmt.Printf("    Error: %s\n", red.Sprint(result.Error))
		} else if result.Banner != "" {
			if len(result.Banner) > 200 {
				fmt.Printf("    Banner: %s...\n", yellow.Sprint(result.Banner[:200]))
			} else {
				fmt.Printf("    Banner: %s\n", yellow.Sprint(result.Banner))
			}
		}

		if len(result.Vulns) > 0 {
			for _, vuln := range result.Vulns {
				severityColor := yellow
				if vuln.Severity == "КРИТИЧЕСКИЙ" {
					severityColor = red
				}
				fmt.Printf("    %s %s: %s\n",
					severityColor.Sprint("VULNERABILITY:"),
					severityColor.Sprint(vuln.CVE),
					vuln.Description)
				if vuln.Exploit != "" {
					fmt.Printf("      Exploit: %s\n", cyan.Sprint(vuln.Exploit))
				}
				if vuln.Solution != "" {
					fmt.Printf("      Solution: %s\n", green.Sprint(vuln.Solution))
				}
			}
		} else {
			fmt.Printf("    %s No vulnerabilities found\n", green.Sprint("✓"))
		}
		fmt.Println()
	}

	// Сводка
	fmt.Printf("%s %s\n", blue.Sprint("[=== SUMMARY ===]"), "")
	fmt.Printf("%s Total ports scanned: %d\n", cyan.Sprint("[*]"), len(results))
	fmt.Printf("%s Vulnerabilities found: %d\n", cyan.Sprint("[*]"), totalVulns)
	fmt.Printf("%s Critical vulnerabilities: %d\n", red.Sprint("[!]"), criticalVulns)
}

func generateReport(target string, results []ScanResult, totalVulns, criticalVulns int) {
	filename := fmt.Sprintf("bloodtrail_scan_%s_%s.md",
		target, time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("%s Error creating report: %v\n", red.Sprint("[-]"), err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Заголовок отчета
	writer.WriteString("# 🩸 BloodTrail - Vulnerability Scan Report\n\n")
	writer.WriteString(fmt.Sprintf("**Scan Target**: `%s`  \n", target))
	writer.WriteString(fmt.Sprintf("**Scan Date**: %s  \n", time.Now().Format("02.01.2006 15:04:05")))
	writer.WriteString(fmt.Sprintf("**Scanner**: EyeOfBlood v2.2  \n"))
	writer.WriteString(fmt.Sprintf("**Report Generator**: EyeOfBlood Security Scanner  \n\n"))

	// Сводка
	writer.WriteString("## 📊 Executive Summary\n\n")
	writer.WriteString(fmt.Sprintf("- **🔍 Ports Scanned**: %d  \n", len(results)))
	writer.WriteString(fmt.Sprintf("- **⚠️  Vulnerabilities Found**: %d  \n", totalVulns))
	writer.WriteString(fmt.Sprintf("- **🔥 Critical Vulnerabilities**: %d  \n", criticalVulns))
	writer.WriteString(fmt.Sprintf("- **🟢 Secure Services**: %d  \n\n", len(results)-totalVulns))

	// Детальные находки
	writer.WriteString("## 🔍 Detailed Findings\n\n")
	for _, result := range results {
		writer.WriteString(fmt.Sprintf("### 🚪 Port %d (%s)\n", result.Port, result.Service))
		if result.Version != "Unknown" {
			writer.WriteString(fmt.Sprintf("**Version**: %s  \n", result.Version))
		}
		if result.Error != "" {
			writer.WriteString(fmt.Sprintf("**Error**: %s  \n", result.Error))
		} else if result.Banner != "" {
			if len(result.Banner) > 300 {
				writer.WriteString(fmt.Sprintf("**Banner**: `%s...`  \n", result.Banner[:300]))
			} else {
				writer.WriteString(fmt.Sprintf("**Banner**: `%s`  \n", result.Banner))
			}
		}

		if len(result.Vulns) > 0 {
			writer.WriteString("**Detected Vulnerabilities**:  \n\n")
			for _, vuln := range result.Vulns {
				severityIcon := "🟡"
				if vuln.Severity == "КРИТИЧЕСКИЙ" {
					severityIcon = "🔴"
				}
				writer.WriteString(fmt.Sprintf("#### %s **%s** (%s)  \n", severityIcon, vuln.CVE, vuln.Severity))
				writer.WriteString(fmt.Sprintf("**Description**: %s  \n", vuln.Description))
				writer.WriteString(fmt.Sprintf("**Risk Level**: %s  \n", vuln.Severity))
				if vuln.Exploit != "" {
					writer.WriteString(fmt.Sprintf("**Exploitation Method**: `%s`  \n", vuln.Exploit))
				}
				writer.WriteString(fmt.Sprintf("**Recommendation**: %s  \n\n", vuln.Solution))
			}
		} else {
			writer.WriteString("**🟢 No Vulnerabilities Detected**  \n\n")
		}
	}

	// Дорожная карта атаки
	writer.WriteString("## 🗺️ Attack Roadmap\n\n")
	writer.WriteString("### 🎯 Recommended Attack Path:\n\n")

	hasCritical := false
	for _, result := range results {
		for _, vuln := range result.Vulns {
			if vuln.Severity == "КРИТИЧЕСКИЙ" {
				writer.WriteString(fmt.Sprintf("1. **Attack via %s** on port %d  \n", vuln.CVE, result.Port))
				writer.WriteString(fmt.Sprintf("   - %s  \n", vuln.Description))
				writer.WriteString(fmt.Sprintf("   - Use: `%s`  \n", vuln.Exploit))
				writer.WriteString(fmt.Sprintf("   - Expected Result: Remote access acquisition  \n\n"))
				hasCritical = true
			}
		}
	}

	if !hasCritical {
		writer.WriteString("No critical vulnerabilities found for attack path construction.\n")
	}

	// Рекомендации по защите
	writer.WriteString("## 🛡️ Security Recommendations\n\n")
	writer.WriteString("1. **Immediately install all security updates**  \n")
	writer.WriteString("2. **Close unused ports** on the firewall  \n")
	writer.WriteString("3. **Regularly conduct vulnerability scans**  \n")
	writer.WriteString("4. **Implement intrusion detection system**  \n")
	writer.WriteString("5. **Configure network activity monitoring**  \n\n")

	writer.WriteString("---\n")
	writer.WriteString("*Report automatically generated with EyeOfBlood v2.2*  \n")
	writer.WriteString("*For professional security testing services, contact @whitegertsok*  \n")

	err = writer.Flush()
	if err != nil {
		fmt.Printf("%s Error saving report to disk: %v\n", red.Sprint("[-]"), err)
		return
	}

	fmt.Printf("%s Full report saved to: %s\n", green.Sprint("[+]"), cyan.Sprint(filename))
	fmt.Printf("%s Report ready for delivery to client!\n", green.Sprint("[+]"))
}
