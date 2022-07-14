// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package socklimit

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadRake returns the embedded CollectionSpec for rake.
func loadRake() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_RakeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load rake: %w", err)
	}

	return spec, err
}

// loadRakeObjects loads rake and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *rakeObjects
//     *rakePrograms
//     *rakeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadRakeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadRake()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// rakeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type rakeSpecs struct {
	rakeProgramSpecs
	rakeMapSpecs
}

// rakeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type rakeProgramSpecs struct {
	FilterIpv4 *ebpf.ProgramSpec `ebpf:"filter_ipv4"`
	FilterIpv6 *ebpf.ProgramSpec `ebpf:"filter_ipv6"`
	TestIpv4   *ebpf.ProgramSpec `ebpf:"test_ipv4"`
	TestIpv6   *ebpf.ProgramSpec `ebpf:"test_ipv6"`
}

// rakeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type rakeMapSpecs struct {
	Countmin         *ebpf.MapSpec `ebpf:"countmin"`
	Stats            *ebpf.MapSpec `ebpf:"stats"`
	TestSingleResult *ebpf.MapSpec `ebpf:"test_single_result"`
}

// rakeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadRakeObjects or ebpf.CollectionSpec.LoadAndAssign.
type rakeObjects struct {
	rakePrograms
	rakeMaps
}

func (o *rakeObjects) Close() error {
	return _RakeClose(
		&o.rakePrograms,
		&o.rakeMaps,
	)
}

// rakeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadRakeObjects or ebpf.CollectionSpec.LoadAndAssign.
type rakeMaps struct {
	Countmin         *ebpf.Map `ebpf:"countmin"`
	Stats            *ebpf.Map `ebpf:"stats"`
	TestSingleResult *ebpf.Map `ebpf:"test_single_result"`
}

func (m *rakeMaps) Close() error {
	return _RakeClose(
		m.Countmin,
		m.Stats,
		m.TestSingleResult,
	)
}

// rakePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadRakeObjects or ebpf.CollectionSpec.LoadAndAssign.
type rakePrograms struct {
	FilterIpv4 *ebpf.Program `ebpf:"filter_ipv4"`
	FilterIpv6 *ebpf.Program `ebpf:"filter_ipv6"`
	TestIpv4   *ebpf.Program `ebpf:"test_ipv4"`
	TestIpv6   *ebpf.Program `ebpf:"test_ipv6"`
}

func (p *rakePrograms) Close() error {
	return _RakeClose(
		p.FilterIpv4,
		p.FilterIpv6,
		p.TestIpv4,
		p.TestIpv6,
	)
}

func _RakeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed rake_bpfel.o
var _RakeBytes []byte
