package caretta

import "github.com/gelonsoft/caretta/pkg/k8s"

type IPResolver interface {
	ResolveIP(ip string) k8s.Workload
	StartWatching() error
	StopWatching()
}
