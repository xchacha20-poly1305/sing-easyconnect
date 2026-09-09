package easyconnect

import (
	"os"

	E "github.com/sagernet/sing/common/exceptions"
)

// Material is a certificate or key provided either inline or as a file path.
type Material struct {
	Path    string
	Content []byte
}

func (m Material) IsSet() bool {
	return m.Path != "" || len(m.Content) > 0
}

func (m Material) Validate(name string) error {
	if m.Path != "" && len(m.Content) > 0 {
		return E.Extend(ErrMaterialSourceConflict, name)
	}
	return nil
}

func loadMaterial(material Material) ([]byte, error) {
	if len(material.Content) > 0 {
		return material.Content, nil
	}
	if material.Path == "" {
		return nil, nil
	}
	content, err := os.ReadFile(material.Path)
	if err != nil {
		return nil, E.Cause(err, "read ", material.Path)
	}
	return content, nil
}
