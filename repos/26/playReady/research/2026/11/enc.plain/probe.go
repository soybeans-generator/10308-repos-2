// scan/main.go — find the prv buffer and the decrypted 0x2229f0 block in mfpmp
package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	k32      = windows.NewLazySystemDLL("kernel32.dll")
	vqEx     = k32.NewProc("VirtualQueryEx")
	readProc = k32.NewProc("ReadProcessMemory")
)

type mbi struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	_pad              uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func regions(h windows.Handle) [][2]uintptr {
	var out [][2]uintptr
	var info mbi
	addr := uintptr(0)
	for {
		r, _, _ := vqEx.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info))
		if r == 0 || info.RegionSize == 0 {
			break
		}
		if info.State == 0x1000 && info.Protect&0xCC != 0 &&
			info.RegionSize > 0 && info.RegionSize <= 0x4000000 {
			out = append(out, [2]uintptr{info.BaseAddress, info.RegionSize})
		}
		next := info.BaseAddress + info.RegionSize
		if next <= addr {
			break
		}
		addr = next
		if addr > 0x7FFFFFFF0000 {
			break
		}
	}
	return out
}

func read(h windows.Handle, base, size uintptr) ([]byte, bool) {
	b := make([]byte, size)
	var got uintptr
	r, _, _ := readProc.Call(uintptr(h), base, uintptr(unsafe.Pointer(&b[0])),
		size, uintptr(unsafe.Pointer(&got)))
	if r == 0 || got == 0 {
		return nil, false
	}
	return b[:got], true
}

func find(h windows.Handle, regs [][2]uintptr, needle []byte, limit int) {
	n := 0
	for _, rg := range regs {
		data, ok := read(h, rg[0], rg[1])
		if !ok {
			continue
		}
		off := 0
		for {
			i := indexOf(data[off:], needle)
			if i < 0 || n >= limit {
				break
			}
			abs := off + i
			lo, hi := abs-0x20, abs+0x60
			if lo < 0 {
				lo = 0
			}
			if hi > len(data) {
				hi = len(data)
			}
			fmt.Printf("    @0x%x  %x\n", rg[0]+uintptr(abs), data[lo:hi])
			n++
			off = abs + 1
		}
		if n >= limit {
			return
		}
	}
	if n == 0 {
		fmt.Println("    none")
	}
}

func indexOf(h, n []byte) int {
	if len(n) == 0 || len(h) < len(n) {
		return -1
	}
	first := n[0]
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i] == first {
			match := true
			for j := 1; j < len(n); j++ {
				if h[i+j] != n[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

func main() {
	prv, err := os.ReadFile("extracted.enc.prv")
	if err != nil {
		panic(err)
	}
	needles := []struct {
		name string
		b    []byte
	}{
		{"prv16", prv[:16]},
		{"prv32", prv[:32]},
		{"blk2229f0", []byte{0x41, 0xBA, 0xB9, 0, 0, 0, 0x48, 0x8D, 0x55, 0x8F}},
	}

	seen := map[uint32]bool{}
	fmt.Println("polling; start playback now")
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err == nil {
			pe := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
			if err = windows.Process32First(snap, &pe); err == nil {
				for {
					if windows.UTF16ToString(pe.ExeFile[:]) == "mfpmp.exe" && !seen[pe.ProcessID] {
						seen[pe.ProcessID] = true
						pid := pe.ProcessID
						fmt.Printf("=== pid %d\n", pid)
						h, err := windows.OpenProcess(
							windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
							false, pid)
						if err != nil {
							fmt.Printf("    open failed: %v\n", err)
						} else {
							regs := regions(h)
							fmt.Printf("    regions %d\n", len(regs))
							for _, nd := range needles {
								fmt.Printf("  %s:\n", nd.name)
								find(h, regs, nd.b, 3)
							}
							windows.CloseHandle(h)
						}
					}
					if err = windows.Process32Next(snap, &pe); err != nil {
						break
					}
				}
			}
			windows.CloseHandle(snap)
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Println("done")
}
