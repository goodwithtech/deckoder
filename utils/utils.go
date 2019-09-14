package utils

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"

	"github.com/goodwithtech/deckoder/types"
)

// CacheDir :
func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "deckoder")
	return dir
}

// StringInSlice :
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// CreateFilterPathFunc :
func CreateFilterPathFunc(filenames []string) types.FilterFunc {
	return func(h *tar.Header) (bool, error) {
		filePath := filepath.Clean(h.Name)
		fileName := filepath.Base(filePath)
		if strings.HasPrefix(fileName, ".wh.") {
			return true, nil
		}
		return StringInSlice(filePath, filenames) || StringInSlice(fileName, filenames), nil
	}
}
