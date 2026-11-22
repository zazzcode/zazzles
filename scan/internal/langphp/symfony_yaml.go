package langphp

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"gopkg.in/yaml.v3"
)

const symfonyConfigLimit = 1 << 20

func readSymfonyConfig(root, file string) (analysis.Evidence, bool) {
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil || !info.Mode().IsRegular() || info.Size() > symfonyConfigLimit {
		return analysis.Evidence{}, false
	}
	return parse.NewTextSources(root).ReadBounded(file, symfonyConfigLimit)
}

func symfonyYAML(text string) (*yaml.Node, bool) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var doc, extra yaml.Node
	err := decoder.Decode(&doc)
	if errors.Is(err, io.EOF) {
		return &yaml.Node{Kind: yaml.MappingNode}, true
	}
	if err != nil || !errors.Is(decoder.Decode(&extra), io.EOF) || len(doc.Content) != 1 || !symfonyYAMLTags(doc.Content[0]) {
		return nil, false
	}
	return doc.Content[0], true
}

func symfonyYAMLTags(node *yaml.Node) bool {
	if tag := node.ShortTag(); strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!") {
		switch tag {
		case "!tagged_iterator", "!service", "!php/const":
		default:
			return false
		}
	}
	for _, item := range node.Content {
		if !symfonyYAMLTags(item) {
			return false
		}
	}
	return true
}

func symfonyYAMLValue(node *yaml.Node, key string) *yaml.Node {
	if node != nil && node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				return node.Content[i+1]
			}
		}
	}
	return nil
}

func symfonyYAMLString(node *yaml.Node) string {
	if node != nil && node.Kind == yaml.ScalarNode {
		return node.Value
	}
	return ""
}

func symfonyYAMLOrigin(src analysis.Evidence, node *yaml.Node) analysis.Evidence {
	start := 0
	for line := 1; line < node.Line; line++ {
		next := strings.IndexByte(src.Text[start:], '\n')
		if next < 0 {
			break
		}
		start += next + 1
	}
	end := len(src.Text)
	if next := strings.IndexByte(src.Text[start:], '\n'); next >= 0 {
		end = start + next
	}
	// YAML columns count characters, whereas report spans count bytes.
	line := []rune(src.Text[start:end])
	if node.Column > 0 && node.Column <= len(line)+1 {
		start += len(string(line[:node.Column-1]))
	}
	return parse.TextRange(src, start, end, "entry_registration")
}
