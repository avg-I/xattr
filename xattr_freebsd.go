package xattr

import (
	"syscall"
)

const (
	extattr_namespace_user = 1
)

// Retrieve extended attribute data associated with path.
func Getxattr(path, name string) ([]byte, error) {
	// find size.
	size, err := extattr_get_file(path, extattr_namespace_user, name, nil, 0)
	if err != nil {
		return nil, &XAttrError{"extattr_get_file", path, name, err}
	}
	buf := make([]byte, size)
	if size == 0 {
		return buf, nil
	}
	// Read into buffer of that size.
	read, err := extattr_get_file(path, extattr_namespace_user, name, &buf[0], size)
	if err != nil {
		return nil, &XAttrError{"extattr_get_file", path, name, err}
	}
	return buf[:read], nil
}

// Retrieves a list of names of extended attributes associated with the
// given path in the file system.
func Listxattr(path string) ([]string, error) {
	// find size.
	size, err := extattr_list_file(path, extattr_namespace_user, nil, 0)
	if err != nil {
		return nil, &XAttrError{"extattr_list_file", path, "", err}
	}
	if size == 0 {
		return make([]string, 0), nil
	}
	buf := make([]byte, size)
	// Read into buffer of that size.
	read, err := extattr_list_file(path, extattr_namespace_user, &buf[0], size)
	if err != nil {
		return nil, &XAttrError{"extattr_list_file", path, "", err}
	}
	return attrListToStrings(buf[:read]), nil
}

// Associates name and data together as an attribute of path.
func Setxattr(path, name string, data []byte) error {
	written, err := extattr_set_file(path, extattr_namespace_user, name, &data[0], len(data))
	if err != nil {
		return &XAttrError{"extattr_set_file", path, name, err}
	}
	if written != len(data) {
		return &XAttrError{"extattr_set_file", path, name, syscall.E2BIG}
	}
	return nil
}

// Remove the attribute.
func Removexattr(path, name string) error {
	if err := extattr_delete_file(path, extattr_namespace_user, name); err != nil {
		return &XAttrError{"extattr_delete_file", path, name, err}
	}
	return nil
}

// Convert a sequnce of attribute name entries to a []string.
// Each entry consists of a single byte containing the length
// of the attribute name, followed by the attribute name.
// The name is _not_ terminated by NUL.
func attrListToStrings(buf []byte) []string {
	var result []string
	index := 0
	for index < len(buf) {
		next := index + 1 + int(buf[index])
		result = append(result, string(buf[index+1:next]))
		index = next
	}
	return result
}
