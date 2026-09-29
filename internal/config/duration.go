package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that also accepts day ("d") and week ("w")
// units, e.g. "30d" or "2w", in addition to Go duration syntax.
type Duration time.Duration

// ParseDuration parses Go durations plus d/w suffixes. "90d12h" is accepted.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var total time.Duration
	rest := s
	for rest != "" {
		i := 0
		for i < len(rest) && (rest[i] >= '0' && rest[i] <= '9') {
			i++
		}
		if i == 0 || i == len(rest) {
			break
		}
		unit := rest[i]
		if unit != 'd' && unit != 'w' && unit != 'y' {
			break
		}
		n, err := strconv.Atoi(rest[:i])
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		switch unit {
		case 'd':
			total += time.Duration(n) * 24 * time.Hour
		case 'w':
			total += time.Duration(n) * 7 * 24 * time.Hour
		case 'y':
			total += time.Duration(n) * 365 * 24 * time.Hour
		}
		rest = rest[i+1:]
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q (use e.g. 30d, 12h, 10s)", s)
		}
		total += d
	}
	return total, nil
}

// UnmarshalYAML implements yaml.Unmarshaler for scalar values.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration in Go syntax.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }
