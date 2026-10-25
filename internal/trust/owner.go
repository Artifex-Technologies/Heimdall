package trust

import (
	"os"
	"syscall"
)

// chownLike gives a restored file the owner of its folder (a file in the user's home goes back to the user, not to root).
func chownLike(path string, folder os.FileInfo) {
	if st, ok := folder.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
