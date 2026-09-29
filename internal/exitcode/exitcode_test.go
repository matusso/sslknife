package exitcode

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

func TestCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, OK},
		{"plain", errors.New("x"), Error},
		{"coded", New(Usage, "bad"), Usage},
		{"wrapped coded", fmt.Errorf("ctx: %w", With(Auth, errors.New("no"))), Auth},
		{"silent", Silent(CheckFailed), CheckFailed},
		{"not exist", fmt.Errorf("open: %w", fs.ErrNotExist), NotFound},
		{"canceled", context.Canceled, Interrupted},
	}
	for _, tt := range tests {
		if got := Code(tt.err); got != tt.want {
			t.Errorf("%s: Code() = %d, want %d", tt.name, got, tt.want)
		}
	}
	if With(Usage, nil) != nil {
		t.Error("With(nil) should be nil")
	}
	if !IsSilent(Silent(1)) || IsSilent(errors.New("x")) {
		t.Error("IsSilent")
	}
}
