package main

import (
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: gostrings <binary>")
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var strs []string
	if asElf, parseErr := elf.NewFile(f); parseErr == nil {
		strs, err = parseElf(asElf)
	} else if asMacho, parseErr := macho.NewFile(f); parseErr == nil {
		strs, err = parseMacho(asMacho)
	} else {
		panic("Unknown binary format")
	}
	if err != nil {
		panic(err)
	}
	sort.Strings(strs)
	for _, s := range strs {
		fmt.Println(s)
	}
}

func parseElf(f *elf.File) ([]string, error) {
	// Collect data from all relevant sections
	dataSections := make(map[uintptr][]byte)
	for _, section := range f.Sections {
		if section.Type == elf.SHT_NOBITS {
			continue
		}
		// TODO: determine which sections can have strings in them
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		dataSections[uintptr(section.Addr)] = data
	}

	stringMap := map[string]struct{}{}

	ptrSize := ptrSizeForCpuElf(f.Class)

	// Iterate over all sections to find pointers and extract strings from the collected sections
	for _, section := range f.Sections {
		if section.Type == elf.SHT_NOBITS {
			continue
		}
		sectionData, err := section.Data()
		if err != nil {
			return nil, err
		}
		for _, str := range findStringsInSection(ptrSize, f.ByteOrder, sectionData, dataSections) {
			stringMap[str] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(stringMap)), nil
}

func parseMacho(f *macho.File) ([]string, error) {
	// Collect data from all relevant sections
	dataSections := make(map[uintptr][]byte)
	for _, section := range f.Sections {
		// TODO: determine which sections can have strings in them
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		dataSections[uintptr(section.Addr)] = data
	}

	stringMap := map[string]struct{}{}

	ptrSize := ptrSizeForCpuMacho(f.Cpu)

	// Iterate over all sections to find pointers and extract strings from the collected sections
	for _, section := range f.Sections {
		sectionData, err := section.Data()
		if err != nil {
			return nil, err
		}
		for _, str := range findStringsInSection(ptrSize, f.ByteOrder, sectionData, dataSections) {
			stringMap[str] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(stringMap)), nil
}

const MIN_LEN = 4
const MAX_LEN = 2048

// findStringsInSection finds pointers in a section and extracts strings from the collected sections
func findStringsInSection(ptrSize int, byteOrder binary.ByteOrder, sectionData []byte, dataSections map[uintptr][]byte) []string {
	var result []string

	for i := 0; i < len(sectionData)-2*ptrSize; i += ptrSize {
		ptr := byteOrder.Uint64(sectionData[i : i+ptrSize])
		length := byteOrder.Uint64(sectionData[i+ptrSize : i+2*ptrSize])
		if length < MIN_LEN || length > MAX_LEN || ptr > 0xffffffffffff0000 {
			continue
		}
		for rodataBaseAddr, rodataData := range dataSections {
			if uintptr(ptr) >= rodataBaseAddr && uintptr(ptr)+uintptr(length) <= rodataBaseAddr+uintptr(len(rodataData)) {
				offset := uintptr(ptr) - rodataBaseAddr
				if offset+uintptr(length) <= uintptr(len(rodataData)) {
					strData := rodataData[offset : offset+uintptr(length)]
					if isPrintable(strData) {
						result = append(result, string(strData))
					}
				} else {
					//fmt.Printf("Invalid offset/length: PTR: %x, LENGTH: %d, OFFSET: %x\n", ptr, length, offset)
				}
			}
		}
	}

	return result
}

func ptrSizeForCpuElf(class elf.Class) int {
	switch class {
	case elf.ELFCLASS32:
		return 4
	case elf.ELFCLASS64:
		return 8
	default:
		panic("unsupported CPU")
	}
}

func ptrSizeForCpuMacho(cpu macho.Cpu) int {
	switch cpu {
	case macho.Cpu386:
		return 4
	case macho.CpuAmd64:
		return 8
	case macho.CpuArm:
		return 4
	case macho.CpuArm64:
		return 8
	default:
		panic("unsupported CPU")
	}
}

// isPrintable checks if the data contains printable ASCII characters
func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
