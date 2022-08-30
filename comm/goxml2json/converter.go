package xml2json

import (
	"bytes"
	"io"
)

// Convert converts the given XML document to JSON
func convert(r io.Reader, typeMap map[string]string, converter func(node *Node) *Node) (*bytes.Buffer, error) {
	// Decode XML document
	root := &Node{}
	err := NewDecoder(r, typeMap).Decode(root)
	if err != nil {
		return nil, err
	}

	// Then encode it in JSON
	buf := new(bytes.Buffer)
	err = NewEncoder(buf).Encode(converter(root))
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func Convert(r io.Reader) (*bytes.Buffer, error) {
	return convert(r, map[string]string{}, func(node *Node) *Node {
		return node
	})
}

func ConvertRemoveRoot(r io.Reader) (*bytes.Buffer, error) {
	typeMap := map[string]string{}

	typeMap["CreateTime"] = "int64"
	typeMap["AuthorizationCodeExpiredTime"] = "int64"

	return convert(r, typeMap, func(node *Node) *Node {
		child := node.Children["xml"][0]

		return child
	})
}
