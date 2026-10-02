// Package power keeps the machine awake while a transfer is running.
//
// An idle laptop that goes to sleep stops its network, which breaks a transfer
// ("broken pipe"). Holding a sleep assertion for the duration of a transfer
// prevents idle sleep (the screen may still turn off). It cannot prevent the
// user closing the lid or choosing Sleep, which the operating system always honors.
package power

// KeepAwake asks the OS not to sleep from idleness until the returned release
// func is called. It never fails: if the platform has no way to do it, the
// release is a no-op. Release may be called more than once.
func KeepAwake(reason string) (release func()) { return keepAwake(reason) }
