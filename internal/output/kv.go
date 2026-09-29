package output

import (
	"fmt"
	"io"
	"strings"
)

// KV renders aligned "Label: value" blocks, optionally under headings.
// Empty values are skipped so renderers can add optional fields freely.
type KV struct {
	style Style
	items []kvItem
}

type kvItem struct {
	heading string
	key     string
	values  []string
}

// NewKV creates a key/value block.
func NewKV(style Style) *KV { return &KV{style: style} }

// Heading starts a new titled section.
func (k *KV) Heading(title string) *KV {
	k.items = append(k.items, kvItem{heading: title})
	return k
}

// Add adds a field; skipped when value is empty.
func (k *KV) Add(key, value string) *KV {
	if value == "" {
		return k
	}
	k.items = append(k.items, kvItem{key: key, values: []string{value}})
	return k
}

// Addf adds a formatted field.
func (k *KV) Addf(key, format string, args ...any) *KV {
	return k.Add(key, fmt.Sprintf(format, args...))
}

// List adds a multi-line field; skipped when values is empty.
func (k *KV) List(key string, values []string) *KV {
	if len(values) == 0 {
		return k
	}
	k.items = append(k.items, kvItem{key: key, values: values})
	return k
}

// Render writes all sections. Keys are aligned per section.
func (k *KV) Render(w io.Writer) error {
	var b strings.Builder
	start := 0
	for start < len(k.items) {
		end := start + 1
		for end < len(k.items) && k.items[end].heading == "" {
			end++
		}
		section := k.items[start:end]
		indent := ""
		if section[0].heading != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(k.style.Bold(section[0].heading) + "\n")
			section = section[1:]
			indent = "  "
		}
		width := 0
		for _, it := range section {
			if n := VisibleWidth(it.key); n > width {
				width = n
			}
		}
		for _, it := range section {
			pad := strings.Repeat(" ", width-VisibleWidth(it.key))
			label := k.style.Dim(it.key+":") + pad + " "
			b.WriteString(indent + label + it.values[0] + "\n")
			cont := indent + strings.Repeat(" ", width+2)
			for _, v := range it.values[1:] {
				b.WriteString(cont + v + "\n")
			}
		}
		start = end
	}
	_, err := io.WriteString(w, b.String())
	return err
}
