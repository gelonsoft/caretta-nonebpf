package caretta

import (
	"encoding/binary"
	"fmt"
	"github.com/gelonsoft/caretta/pkg/netstat"
	"log"
	"net"
)

type Probes struct {
}

var activeThroughput = ConnectionThroughputStats{
	BytesSent:     1,
	BytesReceived: 1,
	IsActive:      1,
}

var inactiveThroughput = ConnectionThroughputStats{
	BytesSent:     1,
	BytesReceived: 1,
	IsActive:      1,
}
var nullSockAddr = &netstat.SockAddr{
	IP:   net.IPv4(0, 0, 0, 0),
	Port: 0,
}
var nullPid = &netstat.Process{
	Pid: -1,
}

func LoadProbes() (Probes, map[ConnectionIdentifier]ConnectionThroughputStats, error) {

	var conns = make(map[ConnectionIdentifier]ConnectionThroughputStats)

	// TCP sockets
	var socks []netstat.SockTabEntry
	//log.Printf("Started probe")
	socks, err := netstat.TCPSocks(netstat.NoopFilter)

	if err != nil {
		return Probes{}, nil, fmt.Errorf("error query tcp socks - %v", err)
	}
	log.Printf("Probe done, found %d links", len(socks))

	var localIPs = []net.IP{}

	ifaces, err := net.Interfaces()
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
			localIPs = append(localIPs, ip)
		}
	}

	var localListens = []netstat.SockAddr{}

	for _, e := range socks {
		if e.LocalAddr != nil && e.State.String() == "LISTEN" {

			if e.LocalAddr.IP.Equal(nullSockAddr.IP) {
				for _, localIP := range localIPs {
					localListens = append(localListens, netstat.SockAddr{IP: localIP, Port: e.LocalAddr.Port})
					//log.Printf("Add listen #1 IP & port " + localIP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)))
				}
			} else {
				localListens = append(localListens, *e.LocalAddr)
				//log.Printf("Add listen #2 IP & port " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)))
			}
		}
	}

	for _, e := range socks {
		if e.State.String() == "LISTEN" {
			continue
		}
		if e.RemoteAddr == nil {
			e.RemoteAddr = nullSockAddr
		}
		if e.LocalAddr == nil {
			e.LocalAddr = nullSockAddr
		}
		if e.Process == nil {
			e.Process = nullPid
		}
		var connRole = ClientConnectionRole
		var changeSourceAndTarget = false
		for _, localIpPort := range localListens {
			var sourceListens = localIpPort.Port == e.LocalAddr.Port && localIpPort.IP.Equal(e.LocalAddr.IP)
			var targetListens = localIpPort.Port == e.RemoteAddr.Port && localIpPort.IP.Equal(e.RemoteAddr.IP)
			if sourceListens || targetListens {
				connRole = ServerConnectionRole
				if !targetListens && sourceListens {
					changeSourceAndTarget = true
				}
			}
		}

		var conn1 ConnectionIdentifier
		if changeSourceAndTarget {
			conn1 = ConnectionIdentifier{
				Id:  e.UID,
				Pid: uint32(e.Process.Pid),
				Tuple: ConnectionTuple{
					DstIp:   binary.LittleEndian.Uint32(e.LocalAddr.IP),
					SrcIp:   binary.LittleEndian.Uint32(e.RemoteAddr.IP),
					DstPort: e.LocalAddr.Port,
					SrcPort: e.RemoteAddr.Port,
				},
				Role: uint32(connRole),
			}
			//log.Printf("Connection #1 role=" + strconv.Itoa(connRole) + " for " + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)) + "->" + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)))
		} else {
			conn1 = ConnectionIdentifier{
				Id:  e.UID,
				Pid: uint32(e.Process.Pid),
				Tuple: ConnectionTuple{
					DstIp:   binary.LittleEndian.Uint32(e.RemoteAddr.IP),
					SrcIp:   binary.LittleEndian.Uint32(e.LocalAddr.IP),
					DstPort: e.RemoteAddr.Port,
					SrcPort: e.LocalAddr.Port,
				},
				Role: uint32(connRole),
			}
			//log.Printf("Connection #2 role=" + strconv.Itoa(connRole) + " for " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)) + "->" + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)))
		}
		//log.Printf("Found link: %d p=%d %s:%d->%s:%d", conn1.Id, conn1.Pid, IP(conn1.Tuple.SrcIp).String(), conn1.Tuple.SrcIp, IP(conn1.Tuple.DstIp).String(), conn1.Tuple.DstPort)
		conns[conn1] = activeThroughput
	}

	return Probes{}, conns, nil
}

func (objs *Probes) UnloadProbes() error {
	// if any close operation fails, will continue to try closing the rest of the struct,
	// and return the first error
	var resultErr error
	resultErr = nil

	return resultErr
}
