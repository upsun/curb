package policy

// LandlockPaths groups directory and file paths for Landlock rule construction.
// Landlock requires different access rights for files vs directories (e.g.
// ReadDir is invalid on a regular file), so they must be handled separately.
type LandlockPaths struct {
	RODirs  []string
	ROFiles []string
	RWDirs  []string
	RWFiles []string
	Exec    []string
}
