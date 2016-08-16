package xattr

import (
	"strings"
	"syscall"
)

type extattr_namespace int

const (
	extattr_namespace_user   = extattr_namespace(1)
	extattr_namespace_system = extattr_namespace(2)

	extattr_namespace_user_prefix   = "user."
	extattr_namespace_system_prefix = "system."
)

// Retrieve extended attribute data associated with path.
func Getxattr(path, name string) ([]byte, error) {
	namespace, name := parseAttrName(name)
	// Find size.
	size, err := extattr_get_file(path, int(namespace), name, nil, 0)
	if err != nil {
		return nil, &XAttrError{"extattr_get_file", path, name, err}
	}
	buf := make([]byte, size)
	if size == 0 {
		return buf, nil
	}
	// Read into buffer of that size.
	read, err := extattr_get_file(path, int(namespace), name, &buf[0], size)
	if err != nil {
		return nil, &XAttrError{"extattr_get_file", path, name, err}
	}
	return buf[:read], nil
}

// Retrieves a list of names of extended attributes associated with the
// given path in the file system.
func Listxattr(path string) ([]string, error) {
	userlist, err := listxattr_impl(path, extattr_namespace_user)
	if err != nil {
		return nil, err
	}
	systemlist, err := listxattr_impl(path, extattr_namespace_system)
	// Regular users are not allowed to see system attributes.
	if err != nil && err.Err != syscall.EPERM {
		return nil, err
	}
	list := make([]string, 0, len(userlist)+len(systemlist))
	for _, name := range userlist {
		list = append(list, extattr_namespace_user_prefix+name)
	}
	for _, name := range systemlist {
		list = append(list, extattr_namespace_system_prefix+name)
	}
	return list, nil
}

func listxattr_impl(path string, namespace extattr_namespace) ([]string, *XAttrError) {
	// Find size.
	size, err := extattr_list_file(path, int(namespace), nil, 0)
	if err != nil {
		return nil, &XAttrError{"extattr_list_file", path, "", err}
	}
	if size == 0 {
		return make([]string, 0), nil
	}
	buf := make([]byte, size)
	// Read into buffer of that size.
	read, err := extattr_list_file(path, int(namespace), &buf[0], size)
	if err != nil {
		return nil, &XAttrError{"extattr_list_file", path, "", err}
	}
	return attrListToStrings(buf[:read]), nil
}

// Associates name and data together as an attribute of path.
func Setxattr(path, name string, data []byte) error {
	namespace, name := parseAttrName(name)
	written, err := extattr_set_file(path, int(namespace), name, &data[0], len(data))
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
	namespace, name := parseAttrName(name)
	if err := extattr_delete_file(path, int(namespace), name); err != nil {
		return &XAttrError{"extattr_delete_file", path, name, err}
	}
	return nil
}

// Check if the attribute name has a predefined prefix, trim the prefix
// and return a namespace identifier corresponding to the prefix.
// Treat a name with no recognized prefix as an attribute name
// in the user namespace.
func parseAttrName(name string) (extattr_namespace, string) {
	if strings.HasPrefix(name, extattr_namespace_user_prefix) {
		name := strings.TrimPrefix(name, extattr_namespace_user_prefix)
		return extattr_namespace_user, name
	}
	if strings.HasPrefix(name, extattr_namespace_system_prefix) {
		name := strings.TrimPrefix(name, extattr_namespace_system_prefix)
		return extattr_namespace_system, name
	}
	return extattr_namespace_user, name
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
