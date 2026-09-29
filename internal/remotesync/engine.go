package remotesync

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/matusso/sslknife/internal/inventory"
)

// Store is a remote object store shared by several devices.
type Store interface {
	// Identity names the remote; sync state is kept per identity.
	Identity() string
	// Manifest returns the manifest and its version (0 when there is none).
	Manifest(ctx context.Context) (Manifest, int, error)
	// PutManifest replaces the manifest if its version is still cas, or
	// returns ErrConflict.
	PutManifest(ctx context.Context, m Manifest, cas int) error
	// Get fetches an object with its private material.
	Get(ctx context.Context, k Key) (*Object, int, error)
	// Put writes an object if its version is still cas (0: must not exist)
	// and returns the new version, or returns ErrConflict.
	Put(ctx context.Context, o *Object, cas int) (int, error)
	// Delete removes an object and its history.
	Delete(ctx context.Context, k Key) error
}

// Action is what a sync does with one object.
type Action string

const (
	ActPush         Action = "push"          // new or changed here
	ActPull         Action = "pull"          // new or changed on the remote
	ActMerge        Action = "merge"         // changed on both sides
	ActDeleteLocal  Action = "delete-local"  // deleted on another device
	ActDeleteRemote Action = "delete-remote" // deleted here
)

// Change is one planned or applied change.
type Change struct {
	Action Action `json:"action"`
	Kind   string `json:"kind"`
	Ident  string `json:"ident"`
	Label  string `json:"label"`
	Error  string `json:"error,omitempty"`
}

// Report summarises a sync.
type Report struct {
	Remote   string   `json:"remote"`
	DryRun   bool     `json:"dry_run,omitempty"`
	Objects  int      `json:"objects"` // objects on the remote afterwards
	Changes  []Change `json:"changes"`
	Failed   int      `json:"failed"`
	Attempts int      `json:"attempts"`
}

// Count returns how many changes had action a (and succeeded).
func (r *Report) Count(a Action) int {
	n := 0
	for _, c := range r.Changes {
		if c.Action == a && c.Error == "" {
			n++
		}
	}
	return n
}

// Options tune a sync.
type Options struct {
	DryRun bool
}

const maxAttempts = 5

// Sync merges the local inventory with the remote store.
func Sync(ctx context.Context, inv *inventory.Service, st Store, opts Options) (*Report, error) {
	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		rep, err := syncOnce(ctx, inv, st, opts)
		if err == nil {
			rep.Attempts = attempt
			return rep, nil
		}
		if !errors.Is(err, ErrConflict) {
			return nil, err
		}
		last = err
	}
	return nil, fmt.Errorf("%w; gave up after %d attempts", last, maxAttempts)
}

type step struct {
	key    Key
	action Action
	local  *local
	entry  Entry
}

// plan decides, per object, which side changed since the agreed state.
//
//	local L, remote R, agreed S (digests; "" = absent)
//	L = R            in sync
//	L, R, R = S      local changed          → push
//	L, R, L = S      remote changed         → pull
//	L, R, neither    both changed           → merge
//	L only, S = ""   new here               → push
//	L only, L = S    deleted on the remote  → delete here
//	L only, L ≠ S    deleted there, changed here → push again
//	R only, S = ""   new on the remote      → pull
//	R only, R = S    deleted here           → delete on the remote
//	R only, R ≠ S    deleted here, changed there → pull again
func plan(locals map[Key]*local, m Manifest, state map[Key]string) (steps []step, agreed map[Key]string) {
	agreed = map[Key]string{}
	all := map[Key]bool{}
	for k := range locals {
		all[k] = true
	}
	for k := range m {
		all[k] = true
	}
	keys := slices.SortedFunc(maps.Keys(all), func(a, b Key) int {
		if d := kindOrder[a.Kind] - kindOrder[b.Kind]; d != 0 {
			return d
		}
		return strings.Compare(a.Ident, b.Ident)
	})
	for _, k := range keys {
		l := locals[k]
		e, inRemote := m[k]
		var L string
		if l != nil {
			L = l.Digest()
		}
		R, S := e.Digest, state[k]
		st := step{key: k, local: l, entry: e}
		switch {
		case l != nil && inRemote:
			switch {
			case L == R:
				agreed[k] = L
				continue
			case R == S:
				st.action = ActPush
			case L == S:
				st.action = ActPull
			default:
				st.action = ActMerge
			}
		case l != nil:
			if S != "" && L == S {
				st.action = ActDeleteLocal
			} else {
				st.action = ActPush
			}
		default:
			if S != "" && R == S {
				st.action = ActDeleteRemote
			} else {
				st.action = ActPull
			}
		}
		steps = append(steps, st)
	}
	return steps, agreed
}

func syncOnce(ctx context.Context, inv *inventory.Service, st Store, opts Options) (*Report, error) {
	db := inv.DB
	remote := st.Identity()
	m, mver, err := st.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	state, err := db.SyncStates(ctx, remote)
	if err != nil {
		return nil, err
	}
	locals, err := loadLocal(ctx, db, nil)
	if err != nil {
		return nil, err
	}
	steps, agreed := plan(locals, m, state)
	rep := &Report{Remote: remote, DryRun: opts.DryRun, Changes: []Change{}}
	if opts.DryRun {
		for _, s := range steps {
			rep.Changes = append(rep.Changes, Change{Action: s.action, Kind: s.key.Kind, Ident: s.key.Ident, Label: labelFor(s)})
		}
		rep.Objects = len(m)
		return rep, nil
	}

	next := maps.Clone(m)
	if next == nil {
		next = Manifest{}
	}
	newState := agreed
	var destroy []Key
	for _, s := range steps {
		ch := Change{Action: s.action, Kind: s.key.Kind, Ident: s.key.Ident, Label: labelFor(s)}
		err := apply(ctx, inv, st, s, next, newState, &destroy)
		if errors.Is(err, ErrConflict) || isFatal(err) {
			return nil, err
		}
		if err != nil {
			ch.Error = err.Error()
			rep.Failed++
			// Keep the previous agreement so the object is retried next time.
			if d, ok := state[s.key]; ok {
				newState[s.key] = d
			}
		}
		rep.Changes = append(rep.Changes, ch)
	}
	if !manifestEqual(m, next) {
		if err := st.PutManifest(ctx, next, mver); err != nil {
			return nil, err
		}
	}
	// Objects are removed only once the manifest no longer lists them.
	for _, k := range destroy {
		_ = st.Delete(ctx, k)
	}
	if err := db.ReplaceSyncStates(ctx, remote, newState); err != nil {
		return nil, err
	}
	rep.Objects = len(next)
	return rep, nil
}

// fatalError marks errors that affect every object (authentication,
// connectivity), which abort the sync instead of failing one object.
type fatalError struct{ error }

func (f fatalError) Unwrap() error { return f.error }

// Fatal wraps err so Sync aborts on it. Stores use it for authentication
// and transport failures.
func Fatal(err error) error {
	if err == nil {
		return nil
	}
	return fatalError{err}
}

func isFatal(err error) bool {
	var f fatalError
	return errors.As(err, &f)
}

func labelFor(s step) string {
	if s.local != nil {
		return s.local.Label()
	}
	return shortIdent(s.key.Ident)
}

func apply(ctx context.Context, inv *inventory.Service, st Store, s step, next Manifest, newState map[Key]string, destroy *[]Key) error {
	db := inv.DB
	k := s.key
	switch s.action {
	case ActPush:
		// An object missing from the manifest may still exist as a leftover
		// of an interrupted sync, so it is written without check-and-set.
		cas := -1
		if _, listed := next[k]; listed {
			cas = s.entry.Version
		}
		return push(ctx, inv, st, s.local, cas, next, newState)
	case ActDeleteLocal:
		return deleteLocal(ctx, db, s.local)
	case ActDeleteRemote:
		delete(next, k)
		*destroy = append(*destroy, k)
		return nil
	}
	// Pull or merge: fetch the remote object and apply it here.
	o, ver, err := st.Get(ctx, k)
	if err != nil {
		return err
	}
	defer zeroPrivate(o)
	if o.Key() != k {
		return fmt.Errorf("remote object %s/%s claims to be %s/%s", k.Kind, k.Ident, o.Kind, o.Ident)
	}
	if err := verifyObject(o); err != nil {
		return err
	}
	if s.local == nil {
		err = importObject(ctx, inv, o)
	} else {
		err = applyObject(ctx, db, s.local, o, s.action == ActMerge)
	}
	if err != nil {
		return err
	}
	remoteDigest := o.Digest()
	// Re-read the local object: applying may not reproduce the remote
	// exactly (a name already taken here, a merge), and then this device's
	// result becomes the new shared version.
	locals, err := loadLocal(ctx, db, &k)
	if err != nil {
		return err
	}
	l := locals[k]
	if l == nil {
		return fmt.Errorf("object %s/%s missing after import", k.Kind, k.Ident)
	}
	if l.Digest() == remoteDigest {
		next[k] = Entry{Digest: remoteDigest, Version: ver}
		newState[k] = remoteDigest
		return nil
	}
	return push(ctx, inv, st, l, ver, next, newState)
}

func push(ctx context.Context, inv *inventory.Service, st Store, l *local, cas int, next Manifest, newState map[Key]string) error {
	if err := loadPrivate(ctx, inv.DB, l); err != nil {
		return err
	}
	defer zeroPrivate(l.Object)
	d := l.Digest()
	ver, err := st.Put(ctx, l.Object, cas)
	if err != nil {
		return err
	}
	next[l.Key()] = Entry{Digest: d, Version: ver}
	newState[l.Key()] = d
	return nil
}

func manifestEqual(a, b Manifest) bool {
	return maps.Equal(a, b)
}
