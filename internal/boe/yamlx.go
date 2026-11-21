package boe

import (
	"strings"

	"gopkg.in/yaml.v3"
)

func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func path(n *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		if n = child(n, k); n == nil {
			return nil
		}
	}
	return n
}

func str(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func items(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func isTrue(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && strings.EqualFold(n.Value, "true")
}

// isFalse is true only when the value is set and is false (also yes/no style).
func isFalse(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	switch strings.ToLower(n.Value) {
	case "false", "no", "off":
		return true
	}
	return false
}
