//go:build !windows

package guigio

func spawnServiceProcess(addr, token string, elevated bool) error {
	return defaultSpawn(addr, token, elevated)
}
