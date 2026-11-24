package detect

import "encoding/binary"

// The BPF program memcpy'd raw network-order bytes into __u32 slots, and Go reads
// those slots with the machine's native endianness. Writing the integer back with
// the same byte order therefore reproduces the original byte sequence on any
// architecture (little- or big-endian). This is the single place that detail lives.
// nativeBytes writes v into b in the byte order the kernel stored it. The
// BPF program copies network-order bytes verbatim into __u32 slots, so
// re-emitting the slot in native order restores the original byte sequence.
func nativeBytes(v uint32, b []byte) { binary.NativeEndian.PutUint32(b, v) }
