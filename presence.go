package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework CoreGraphics -framework IOKit
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <IOKit/IOKitLib.h>

// screenLocked: 1 locked, 0 unlocked, -1 unknown (no GUI session).
static int screenLocked(void) {
	CFDictionaryRef d = CGSessionCopyCurrentDictionary();
	if (!d) return -1;
	int locked = 0;
	CFBooleanRef v = CFDictionaryGetValue(d, CFSTR("CGSSessionScreenIsLocked"));
	if (v && CFBooleanGetValue(v)) locked = 1;
	CFBooleanRef on = CFDictionaryGetValue(d, CFSTR("kCGSSessionOnConsoleKey"));
	if (on && !CFBooleanGetValue(on)) locked = 1; // fast user switching: someone else's session is in front
	CFRelease(d);
	return locked;
}

// idleNanos: time since the last keyboard/mouse input, -1 if unknown.
static long long idleNanos(void) {
	io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOHIDSystem"));
	if (!s) return -1;
	long long ns = -1;
	CFTypeRef v = IORegistryEntryCreateCFProperty(s, CFSTR("HIDIdleTime"), kCFAllocatorDefault, 0);
	if (v) {
		if (CFGetTypeID(v) == CFNumberGetTypeID()) CFNumberGetValue((CFNumberRef)v, kCFNumberSInt64Type, &ns);
		CFRelease(v);
	}
	IOObjectRelease(s);
	return ns;
}
*/
import "C"

import (
	"fmt"
	"time"
)

// ownerAtMac says whether someone is using the Mac right now: unlocked screen and input within maxIdle. Only then
// does mode auto try 1Password (its unlock window and Touch ID sheet pull the screen to 1Password); otherwise the
// phone is asked straight away. The reason is for the stderr note.
func ownerAtMac(maxIdle time.Duration) (bool, string) {
	switch C.screenLocked() {
	case 1:
		return false, "the Mac's screen is locked"
	case -1:
		return false, "no one is logged in at the Mac's screen"
	}
	ns := int64(C.idleNanos())
	if ns < 0 {
		return true, ""
	}
	idle := time.Duration(ns)
	if idle > maxIdle {
		return false, fmt.Sprintf("no keyboard or mouse input for %s", idle.Round(time.Minute))
	}
	return true, ""
}
