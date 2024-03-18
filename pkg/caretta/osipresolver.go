package caretta

import (
	"fmt"
	"github.com/gelonsoft/caretta/pkg/k8s"
	"net"
)

type OSIPResolver struct{}

func (resolver *OSIPResolver) ResolveIP(ip string) k8s.Workload {

	addresses, err := net.LookupAddr(ip)
	if err != nil {
		return k8s.Workload{
			Name:      ip,
			Namespace: "Namespace",
			Kind:      "Kind",
		}
	}
	if len(addresses) == 0 {
		fmt.Printf("error: addresses has a length of zero")
		return k8s.Workload{
			Name:      ip,
			Namespace: "Namespace",
			Kind:      "Kind",
		}
	}

	return k8s.Workload{
		Name:      addresses[0] + ":" + ip,
		Namespace: "Namespace",
		Kind:      "Kind",
	}
}

func (resolver *OSIPResolver) StartWatching() error {
	return nil
}
func (resolver *OSIPResolver) StopWatching() {}
