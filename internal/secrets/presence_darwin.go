package secrets

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// LAPolicyDeviceOwnerAuthentication accepts Touch ID, a paired Apple Watch
// or, when neither is available, the macOS login password.
const laPolicyDeviceOwnerAuthentication = 2

var loadLocalAuthentication = sync.OnceValue(func() error {
	_, err := purego.Dlopen("/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication", purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPresenceUnavailable, err)
	}
	return nil
})

// PresenceAvailable reports whether ConfirmPresence can prompt on this Mac.
func PresenceAvailable() error {
	if err := loadLocalAuthentication(); err != nil {
		return err
	}
	ctx := objc.ID(objc.GetClass("LAContext")).Send(objc.RegisterName("new"))
	defer ctx.Send(objc.RegisterName("release"))
	var nserr objc.ID
	if !objc.Send[bool](ctx, objc.RegisterName("canEvaluatePolicy:error:"), laPolicyDeviceOwnerAuthentication, &nserr) {
		return fmt.Errorf("presence confirmation with Touch ID is not available: %s", errorDescription(nserr))
	}
	return nil
}

// ConfirmPresence shows the system Touch ID sheet with reason and blocks
// until the user authenticates or cancels. Apple Watch and the login
// password are accepted as alternatives, as for sudo with pam_tid.
func ConfirmPresence(reason string) error {
	if err := PresenceAvailable(); err != nil {
		return err
	}
	ctx := objc.ID(objc.GetClass("LAContext")).Send(objc.RegisterName("new"))
	defer ctx.Send(objc.RegisterName("release"))
	msg := objc.ID(objc.GetClass("NSString")).Send(objc.RegisterName("alloc")).
		Send(objc.RegisterName("initWithUTF8String:"), reason)
	defer msg.Send(objc.RegisterName("release"))

	// The reply block runs on a private LocalAuthentication queue.
	done := make(chan error, 1)
	reply := objc.NewBlock(func(_ objc.Block, ok bool, nserr objc.ID) {
		if ok {
			done <- nil
			return
		}
		done <- fmt.Errorf("%w: %s", ErrPresenceDenied, errorDescription(nserr))
	})
	defer reply.Release()
	ctx.Send(objc.RegisterName("evaluatePolicy:localizedReason:reply:"), laPolicyDeviceOwnerAuthentication, msg, reply)
	return <-done
}

func errorDescription(nserr objc.ID) string {
	if nserr == 0 {
		return "unknown error"
	}
	d := nserr.Send(objc.RegisterName("localizedDescription"))
	return objc.Send[string](d, objc.RegisterName("UTF8String"))
}
