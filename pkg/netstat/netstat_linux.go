// Package netstat provides primitives for getting socket information on a
// Linux based operating system.
package netstat

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	unix "golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

const (
	pathTCPTab  = "/proc/net/tcp"
	pathTCP6Tab = "/proc/net/tcp6"
	pathUDPTab  = "/proc/net/udp"
	pathUDP6Tab = "/proc/net/udp6"

	pathProcessTCPTab  = "/net/tcp"
	pathProcessTCP6Tab = "/net/tcp6"
	pathProcessUDPTab  = "/net/udp"
	pathProcessUDP6Tab = "/net/udp6"

	ipv4StrLen = 8
	ipv6StrLen = 32
)

var useProcessesTab = os.Getenv("USE_ALL_PROC") != ""

// Socket states
const (
	Established SkState = 0x01
	SynSent             = 0x02
	SynRecv             = 0x03
	FinWait1            = 0x04
	FinWait2            = 0x05
	TimeWait            = 0x06
	Close               = 0x07
	CloseWait           = 0x08
	LastAck             = 0x09
	Listen              = 0x0a
	Closing             = 0x0b
)

var skStates = [...]string{
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"", // CLOSE
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

// Errors returned by gonetstat
var (
	ErrNotEnoughFields = errors.New("gonetstat: not enough fields in the line")
)

func parseIPv4(s string) (net.IP, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return ip, nil
}

func parseIPv6(s string) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	const grpLen = 4
	i, j := 0, 4
	for len(s) != 0 {
		grp := s[0:8]
		u, err := strconv.ParseUint(grp, 16, 32)
		binary.LittleEndian.PutUint32(ip[i:j], uint32(u))
		if err != nil {
			return nil, err
		}
		i, j = i+grpLen, j+grpLen
		s = s[8:]
	}
	return ip, nil
}

func parseAddr(s string) (*SockAddr, error) {
	fields := strings.Split(s, ":")
	if len(fields) < 2 {
		return nil, fmt.Errorf("netstat: not enough fields: %v", s)
	}
	var ip net.IP
	var err error
	switch len(fields[0]) {
	case ipv4StrLen:
		ip, err = parseIPv4(fields[0])
	case ipv6StrLen:
		ip, err = parseIPv6(fields[0])
	default:
		err = fmt.Errorf("netstat: bad formatted string: %v", fields[0])
	}
	if err != nil {
		return nil, err
	}
	v, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return nil, err
	}
	return &SockAddr{IP: ip, Port: uint16(v)}, nil
}

func parseSocktab(r io.Reader, accept AcceptFn) ([]SockTabEntry, error) {
	br := bufio.NewScanner(r)
	tab := make([]SockTabEntry, 0, 4)

	// Discard title
	br.Scan()

	for br.Scan() {
		var e SockTabEntry
		line := br.Text()
		// Skip comments
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 12 {
			return nil, fmt.Errorf("netstat: not enough fields: %v, %v", len(fields), fields)
		}
		addr, err := parseAddr(fields[1])
		if err != nil {
			return nil, err
		}
		e.LocalAddr = addr
		addr, err = parseAddr(fields[2])
		if err != nil {
			return nil, err
		}
		e.RemoteAddr = addr
		u, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, err
		}
		e.State = SkState(u)
		u, err = strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return nil, err
		}
		e.UID = uint32(u)
		e.ino = fields[9]
		if accept(&e) {
			tab = append(tab, e)
		}
	}
	return tab, br.Err()
}

type procFd struct {
	base  string
	pid   int
	sktab []SockTabEntry
	p     *Process
}

const sockPrefix = "socket:["

func getProcName(s []byte) string {
	i := bytes.Index(s, []byte("("))
	if i < 0 {
		return ""
	}
	j := bytes.LastIndex(s, []byte(")"))
	if i < 0 {
		return ""
	}
	if i > j {
		return ""
	}
	return string(s[i+1 : j])
}

func (p *procFd) iterFdDir() {
	// link name is of the form socket:[5860846]
	fddir := path.Join(p.base, "/fd")
	fi, err := os.ReadDir(fddir)
	if err != nil {
		return
	}
	var buf [128]byte

	for _, file := range fi {
		fd := path.Join(fddir, file.Name())
		lname, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(lname, sockPrefix) {
			continue
		}

		for i := range p.sktab {
			sk := &p.sktab[i]
			ss := sockPrefix + sk.ino + "]"
			if ss != lname {
				continue
			}
			if p.p == nil {
				stat, err := os.Open(path.Join(p.base, "stat"))
				if err != nil {
					return
				}
				n, err := stat.Read(buf[:])
				stat.Close()
				if err != nil {
					return
				}
				z := bytes.SplitN(buf[:n], []byte(" "), 3)
				name := getProcName(z[1])
				p.p = &Process{p.pid, name}
			}
			sk.Process = p.p
		}
	}
}

func extractProcInfo(sktab []SockTabEntry) {
	const basedir = "/proc"
	fi, err := os.ReadDir(basedir)
	if err != nil {
		return
	}

	for _, file := range fi {
		if !file.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		base := path.Join(basedir, file.Name())
		proc := procFd{base: base, pid: pid, sktab: sktab}
		proc.iterFdDir()
	}
}

// doNetstat - collect information about network port status
func doNetstat(path string, fn AcceptFn) ([]SockTabEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	tabs, err := parseSocktab(f, fn)
	f.Close()
	if err != nil {
		return nil, err
	}
	extractProcInfo(tabs)
	return tabs, nil
}

func doSubNetstat(subpath string, fn AcceptFn) ([]SockTabEntry, error) {
	const basedir = "/proc"
	fi, err := os.ReadDir(basedir)
	if err != nil {
		return nil, nil
	}

	var inodes = make([]uint64, 0)

	var resultTab = make([]SockTabEntry, 0)

	for _, file := range fi {
		if !file.IsDir() {
			continue
		}
		tabPath := path.Join(basedir, file.Name(), subpath)
		var stat unix.Stat_t
		err = unix.Stat(tabPath, &stat)
		if err != nil {
			continue
		}
		if slices.Contains(inodes, stat.Ino) {
			continue
		}
		inodes = append(inodes, stat.Ino)

		f, err := os.Open(tabPath)
		if err != nil {
			continue
		}
		tabs, err := parseSocktab(f, fn)
		if err != nil {
			continue
		}
		resultTab = append(resultTab, tabs...)
		err = f.Close()
		if err != nil {
			continue
		}
	}
	extractProcInfo(resultTab)
	return resultTab, nil
}

// TCPSocks returns a slice of active TCP sockets containing only those
// elements that satisfy the accept function
func osTCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	if useProcessesTab {
		return doSubNetstat(pathProcessTCPTab, accept)
	} else {
		return doNetstat(pathTCPTab, accept)
	}
}

// TCP6Socks returns a slice of active TCP IPv4 sockets containing only those
// elements that satisfy the accept function
func osTCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	if useProcessesTab {
		return doSubNetstat(pathProcessTCP6Tab, accept)
	} else {
		return doNetstat(pathTCP6Tab, accept)
	}
}

// UDPSocks returns a slice of active UDP sockets containing only those
// elements that satisfy the accept function
func osUDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	if useProcessesTab {
		return doSubNetstat(pathProcessUDPTab, accept)
	} else {
		return doNetstat(pathUDPTab, accept)
	}
}

// UDP6Socks returns a slice of active UDP IPv6 sockets containing only those
// elements that satisfy the accept function
func osUDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	if useProcessesTab {
		return doSubNetstat(pathProcessUDP6Tab, accept)
	} else {
		return doNetstat(pathUDP6Tab, accept)
	}
}

func osGetIPsInterfaceOnly() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ipMap := make(map[string]bool)
	// handle err
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ipMap[ip.String()] = true
		}
	}
	var uniqueIPs []net.IP
	for IP := range ipMap {
		uniqueIPs = append(uniqueIPs, net.IP(IP))
	}

	return uniqueIPs, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func osGetSubProcessIPs() (map[string]bool, error) {
	const basedir = "/proc"
	const subpath = "net/fib_trie"
	fi, err := os.ReadDir(basedir)
	if err != nil {
		return nil, err
	}

	var inodes = make([]uint64, 0)

	var result = make(map[string]bool)

	for _, file := range fi {
		if !file.IsDir() {
			continue
		}
		tabPath := path.Join(basedir, file.Name(), subpath)
		var stat unix.Stat_t
		err = unix.Stat(tabPath, &stat)
		if err != nil {
			continue
		}
		if slices.Contains(inodes, stat.Ino) {
			continue
		}
		inodes = append(inodes, stat.Ino)

		lines, err := readLines(tabPath)
		if err != nil {
			continue
		}

		for i, line := range lines {
			if strings.Contains(line, "/32 host") && i > 0 {
				split := strings.Split(lines[i-1], "|-- ")
				if len(split) == 2 {
					ip := split[1]
					result[ip] = true
				}
			}
		}
	}
	return result, nil
}

func osGetIPs() ([]net.IP, error) {
	if useProcessesTab {
		resultMap := make([]net.IP, 0)
		interfaceIPs, err := osGetIPsInterfaceOnly()
		if err != nil {
			return interfaceIPs, err
		}
		subProcessIPsMap, err := osGetSubProcessIPs()
		if err != nil {
			return interfaceIPs, err
		}
		for _, ip := range interfaceIPs {
			subProcessIPsMap[ip.String()] = true
		}
		for ip := range subProcessIPsMap {
			netIP := net.ParseIP(ip)
			if netIP != nil {
				resultMap = append(resultMap, netIP)
			}
		}
		return resultMap, nil
	} else {
		return osGetIPsInterfaceOnly()
	}
}
