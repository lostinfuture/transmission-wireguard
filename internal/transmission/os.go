package transmission

import "os"

func mkdirTemp() (string, error) { return os.MkdirTemp("", "trdump") }

func removeAll(path string) { _ = os.RemoveAll(path) }
