package easyconnect

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// xmlElement is a lenient tree of one /por/*.csp response. The gateway emits
// documents with duplicated tags, stray comments and non-UTF-8 attributes, so
// the decoder runs in non-strict mode and the tree keeps every sibling.
type xmlElement struct {
	Name       string
	Attributes map[string]string
	Text       string
	Children   []*xmlElement
}

func parseXMLDocument(reader io.Reader) (*xmlElement, error) {
	decoder := xml.NewDecoder(reader)
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity
	root := &xmlElement{Name: ""}
	stack := []*xmlElement{root}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, E.Cause(err, "parse XML document")
		}
		switch typed := token.(type) {
		case xml.StartElement:
			element := &xmlElement{Name: typed.Name.Local}
			if len(typed.Attr) > 0 {
				element.Attributes = make(map[string]string, len(typed.Attr))
				for _, attribute := range typed.Attr {
					element.Attributes[attribute.Name.Local] = attribute.Value
				}
			}
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, element)
			stack = append(stack, element)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			element := stack[len(stack)-1]
			element.Text += string(typed)
		}
	}
	return root, nil
}

// element returns the first descendant with the given name, searching depth
// first. Gateway documents are shallow and tag names are unique enough that a
// name lookup is more robust than a fixed path.
func (e *xmlElement) element(name string) *xmlElement {
	for _, child := range e.Children {
		if child.Name == name {
			return child
		}
		if found := child.element(name); found != nil {
			return found
		}
	}
	return nil
}

// elements returns every descendant with the given name.
func (e *xmlElement) elements(name string) []*xmlElement {
	return common.FlatMap(e.Children, func(child *xmlElement) []*xmlElement {
		if child.Name == name {
			return []*xmlElement{child}
		}
		return child.elements(name)
	})
}

func (e *xmlElement) text(name string) string {
	element := e.element(name)
	if element == nil {
		return ""
	}
	return strings.TrimSpace(element.Text)
}

func (e *xmlElement) attribute(name string) string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Attributes[name])
}
