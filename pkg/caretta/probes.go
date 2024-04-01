package caretta

import (
	"encoding/binary"
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
	"log"
	"net"
	"strconv"
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

	var localIPs = []netstat.SockAddr{}

	for _, e := range socks {
		if e.LocalAddr != nil && e.State.String() == "LISTEN" {
			log.Printf("Add listen IP & port " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)))
			localIPs = append(localIPs, *e.LocalAddr)
		}
	}

	for _, e := range socks {
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
		for _, localIpPort := range localIPs {
			if localIpPort.Port == localIpPort.Port && localIpPort.IP.Equal(e.LocalAddr.IP) {
				log.Printf("Connection is local " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)) + "->" + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)))
				connRole = ServerConnectionRole
			}
		}

		var conn1 = ConnectionIdentifier{
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
