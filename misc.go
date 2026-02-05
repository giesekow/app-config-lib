package configlib

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func GetBaseDirectory() string {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}

	exeDir := filepath.Dir(exePath)
	return exeDir
}

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}
	path = os.ExpandEnv(path)
	path, _ = filepath.Abs(path)
	return path
}
