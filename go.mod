module lmb.io/socklimit

go 1.18

require (
	github.com/cilium/ebpf v0.9.1-0.20220712091325-f4e40e43a052
	github.com/google/gopacket v1.1.18
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.64
)

require kernel.org/pub/linux/libs/security/libcap/psx v1.2.64 // indirect
