package output

import (
	"io"
	"strings"
)

// Node is an element of a printable tree, e.g. a certificate chain.
type Node struct {
	Label    string
	Children []*Node
}

// Add appends a child and returns it.
func (n *Node) Add(label string) *Node {
	c := &Node{Label: label}
	n.Children = append(n.Children, c)
	return c
}

// RenderTree writes n with box-drawing connectors.
func RenderTree(w io.Writer, n *Node) error {
	var b strings.Builder
	b.WriteString(n.Label + "\n")
	renderChildren(&b, n.Children, "")
	_, err := io.WriteString(w, b.String())
	return err
}

func renderChildren(b *strings.Builder, children []*Node, prefix string) {
	for i, c := range children {
		last := i == len(children)-1
		conn, next := "├── ", "│   "
		if last {
			conn, next = "└── ", "    "
		}
		lines := strings.Split(c.Label, "\n")
		b.WriteString(prefix + conn + lines[0] + "\n")
		for _, l := range lines[1:] {
			b.WriteString(prefix + next + l + "\n")
		}
		renderChildren(b, c.Children, prefix+next)
	}
}
