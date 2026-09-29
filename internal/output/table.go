package output

import (
	"io"
	"strings"
)

// Table renders aligned columns. Cells may contain ANSI colour codes.
type Table struct {
	headers []string
	rows    [][]string
}

// NewTable creates a table with the given column headers.
func NewTable(headers ...string) *Table { return &Table{headers: headers} }

// Row appends a row; missing cells are rendered empty.
func (t *Table) Row(cells ...string) { t.rows = append(t.rows, cells) }

// Len returns the number of data rows.
func (t *Table) Len() int { return len(t.rows) }

// Render writes the table. Headers are styled bold/dim when style is enabled.
func (t *Table) Render(w io.Writer, style Style) error {
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = VisibleWidth(h)
	}
	for _, r := range t.rows {
		for i := 0; i < len(r) && i < len(widths); i++ {
			if n := VisibleWidth(r[i]); n > widths[i] {
				widths[i] = n
			}
		}
	}
	var b strings.Builder
	writeRow := func(cells []string, header bool) {
		for i := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			if header {
				cell = style.Bold(cell)
			}
			b.WriteString(cell)
			if i < len(widths)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-VisibleWidth(cell)+2))
			}
		}
		b.WriteString("\n")
	}
	writeRow(t.headers, true)
	for _, r := range t.rows {
		writeRow(r, false)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
