package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	portRange  = flag.String("pr", "1-65535", "Specify port range (e.g., 80-1000)")
	topPorts   = flag.Bool("top-ports", false, "Scan top common ports instead of full range")
	timeout    = flag.Int("t", 5, "Timeout in seconds for each connection attempt")
	rateLimit  = flag.Int("r", 100, "Max concurrent scans (default: 100)")
	retries    = 3
	rateFactor = 1.0 // Adaptive rate limit factor
)

var commonPorts = []int{1, 7, 9, 11, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 42, 49, 53, 67, 68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 96, 98, 106, 109, 110, 111, 113, 119, 123, 129, 135, 137, 138, 139, 143, 161, 162, 179, 199, 220, 256, 389, 427, 443, 444, 445, 465, 500, 502, 512, 513, 514, 520, 523, 554, 587, 623, 631, 636, 873, 901, 989, 990, 992, 993, 995, 1000, 1025, 1080, 1099, 1194, 1214, 1337, 1352, 1433, 1434, 1512, 1521, 1720, 1723, 1755, 1883, 1900, 2000, 2048, 2049, 2082, 2083, 2086, 2087, 20880, 2100, 2200, 2222, 2375, 2376, 2483, 2484, 25565, 2601, 2604, 2947, 3050, 3128, 3260, 3306, 3388, 3389, 3456, 3632, 4000, 4045, 4444, 4500, 4786, 4848, 5000, 5353, 5432, 5555, 5632, 5800, 5900, 5901, 5985, 6000, 6379, 6646, 6667, 7000, 7001, 7070, 7777, 8000, 8080, 8081, 8088, 8181, 8222, 8443, 8888, 9000, 9090, 9200, 9300, 9999, 10000, 11211, 27017, 27018, 50050, 50051, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010, 60011, 60012, 60013, 60014, 60015, 60016, 60017, 60018, 60019, 60020, 60021, 60022, 60023, 60024, 60025, 60026, 60027, 60028, 60029, 60030, 60031, 60032, 60033, 60034, 60035, 60036, 60037, 60038, 60039, 60040, 60041, 60042, 60043, 60044, 60045, 60046, 60047, 60048, 60049, 60050, 60051, 60052, 60053, 60054, 60055, 60056, 60057, 60058, 60059, 60060, 60061, 60062, 60063, 60064, 60065, 60066, 60067, 60068, 60069, 60070, 60071, 60072, 60073, 60074, 60075, 60076, 60077, 60078, 60079, 60080, 60081, 60082, 60083, 60084, 60085, 60086, 60087, 60088, 60089, 60090, 60091, 60092, 60093, 60094, 60095, 60096, 60097, 60098, 60099, 60100, 60101, 60102, 60103, 60104, 60105, 60106, 60107, 60108, 60109, 60110, 60111, 60112, 60113, 60114, 60115, 60116, 60117, 60118, 60119, 60120, 60121, 60122, 60123, 60124, 60125, 60126, 60127, 60128, 60129, 60130, 60131, 60132, 60133, 60134, 60135, 60136, 60137, 60138, 60139, 60140, 60141, 60142, 60143, 60144, 60145, 60146, 60147, 60148, 60149, 60150, 60151, 60152, 60153, 60154, 60155, 60156, 60157, 60158, 60159, 60160, 60161, 60162, 60163, 60164, 60165, 60166, 60167, 60168, 60169, 60170, 60171, 60172, 60173, 60174, 60175, 60176, 60177, 60178, 60179, 60180, 60181, 60182, 60183, 60184, 60185, 60186, 60187, 60188, 60189, 60190, 60191, 60192, 60193, 60194, 60195, 60196, 60197, 60198, 60199, 60200}

func parsePortRange(rangeStr string) ([]int, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, errors.New("invalid port range format")
	}
	start, err1 := strconv.Atoi(parts[0])
	end, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
		return nil, errors.New("invalid port range values")
	}

	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}
	return ports, nil
}

func sanitizeTarget(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		target = strings.Split(target, "//")[1]
	}
	return strings.Split(target, "/")[0] // Remove any trailing paths
}

func grabBanner(host string, port int) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	var banner strings.Builder

	for attempt := 0; attempt < retries; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, time.Duration(*timeout)*time.Second)
		if err != nil {
			adjustRateLimit(false)
			continue
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		if port == 21 {
			fmt.Fprintf(conn, "USER anonymous\r\n")
		} else if port == 3306 {
			conn.Write([]byte("\x03SELECT VERSION();"))
		}

		probes := []string{"\r\n", "\r\n\r\n", "\n\n"}
		for _, probe := range probes {
			fmt.Fprintf(conn, probe)
			time.Sleep(randomDelay(500, 1000))
		}

		buf := make([]byte, 4096)
		for i := 0; i < 5; i++ {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				break
			}
			banner.WriteString(string(buf[:n]))
			time.Sleep(randomDelay(500, 1000))
		}

		if banner.Len() > 0 {
			adjustRateLimit(true)
			return strings.TrimSpace(banner.String())
		}
		time.Sleep(randomDelay(1000, 3000))
	}
	return ""
}

func scanPort(host string, port int, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	time.Sleep(randomDelay(100, 500)) // Random delay to evade detection
	banner := grabBanner(host, port)
	if banner != "" {
		results <- fmt.Sprintf("%s:%d - %s", host, port, banner)
	}
}

func adjustRateLimit(success bool) {
	if success {
		rateFactor *= 0.9 // Speed up if responses are coming
	} else {
		rateFactor *= 1.1 // Slow down if errors occur
	}
	if rateFactor < 0.5 {
		rateFactor = 0.5
	} else if rateFactor > 2.0 {
		rateFactor = 2.0
	}
}

func randomDelay(min, max int) time.Duration {
	return time.Duration(min+rand.Intn(max-min)) * time.Millisecond
}

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()

	var ports []int
	var err error
	if *topPorts {
		ports = commonPorts
	} else {
		ports, err = parsePortRange(*portRange)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	var targets []string
	for scanner.Scan() {
		targets = append(targets, sanitizeTarget(scanner.Text()))
	}

	if len(targets) == 0 {
		fmt.Println("No targets provided!")
		return
	}

	sem := make(chan struct{}, *rateLimit)
	var wg sync.WaitGroup
	results := make(chan string, len(targets)*len(ports))

	go func() {
		for res := range results {
			fmt.Println(res)
		}
	}()

	for _, host := range targets {
		for _, port := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(h string, p int) {
				scanPort(h, p, results, &wg)
				<-sem
			}(host, port)
		}
	}

	wg.Wait()
	close(results)
}
