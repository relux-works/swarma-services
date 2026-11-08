package tails

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Pathspecs are the union of HEAD and index paths: index-only selection would
// miss staged deletions. Never pass an empty list to Git (it means all paths).
// A path shared by HEAD and index is counted only once.
func trackedSelection(root string, index, head []byte) (map[string]bool, map[string]bool, []string, int, error) {
	tracked, submodules := map[string]bool{}, map[string]bool{}
	all := map[string]bool{}
	for kind, data := range [][]byte{index, head} {
		if len(data) > 0 && data[len(data)-1] != 0 {
			return nil, nil, nil, 0, errors.New("invalid_tracked_records")
		}
		rows := bytes.Split(data, []byte{0})
		if len(rows) > MaxRows {
			return nil, nil, nil, 0, errors.New("tracked_path_bound")
		}
		seen := map[string]bool{}
		for _, row := range rows {
			if len(row) == 0 {
				continue
			}
			a := bytes.SplitN(row, []byte{'\t'}, 2)
			if len(a) != 2 {
				return nil, nil, nil, 0, errors.New("invalid_tracked_records")
			}
			fields, p := strings.Fields(string(a[0])), string(a[1])
			if len(fields) != 3 || p == "" || p == "." || len(p) > 4096 || filepath.IsAbs(p) || filepath.ToSlash(filepath.Clean(p)) != p || p == ".." || strings.HasPrefix(p, "../") {
				return nil, nil, nil, 0, errors.New("invalid_tracked_records")
			}
			for _, part := range strings.Split(p, "/") {
				if strings.EqualFold(part, ".git") {
					return nil, nil, nil, 0, errors.New("invalid_tracked_records")
				}
			}
			mode := fields[0]
			if mode != "100644" && mode != "100755" && mode != "120000" && mode != "160000" {
				return nil, nil, nil, 0, errors.New("invalid_tracked_records")
			}
			if kind == 0 {
				if !oidRE.MatchString(fields[1]) || (fields[2] != "0" && fields[2] != "1" && fields[2] != "2" && fields[2] != "3") || seen[p+"\x00"+fields[2]] {
					return nil, nil, nil, 0, errors.New("unmerged_or_invalid_index")
				}
				tracked[p] = true
				seen[p+"\x00"+fields[2]] = true
			} else if seen[p] || !oidRE.MatchString(fields[2]) || (mode == "160000" && fields[1] != "commit") || (mode != "160000" && fields[1] != "blob") {
				return nil, nil, nil, 0, errors.New("invalid_tracked_records")
			}
			seen[p], all[p] = true, true
			if mode == "160000" {
				submodules[p] = true
			}
		}
	}
	// A literal pathspec still recursively matches descendants. File/directory
	// transitions could select an excluded child; refuse this ambiguous scope.
	for p := range all {
		for q := filepath.ToSlash(filepath.Dir(p)); q != "."; q = filepath.ToSlash(filepath.Dir(q)) {
			if all[q] {
				return nil, nil, nil, 0, errors.New("overlapping_tracked_paths")
			}
		}
	}
	if len(all) >= MaxRows {
		return nil, nil, nil, 0, errors.New("tracked_path_bound")
	}
	var safe []string
	excluded, size := 0, 0
	for p := range all {
		size += len(p) + 1
		if sensitive(p) || submodules[p] || !trackedSourceOK(root, p) {
			excluded++
			continue
		}
		safe = append(safe, p)
	}
	// Only an excluded scope needs an explicit argv list. With no exclusions,
	// every HEAD/index path passed the same admission checks, so full tracked
	// status has exactly the admitted scope and needs no pathspec bytes.
	if excluded > 0 && size > 64<<10 {
		return nil, nil, nil, 0, errors.New("tracked_pathspec_bound")
	}
	sort.Strings(safe)
	return tracked, submodules, safe, excluded, nil
}

// Metadata only. Do not follow a symlinked ancestor or admit a special file to
// Git's content check. Missing paths are admitted so deletions remain visible.
func trackedSourceOK(root, p string) bool {
	parts := strings.Split(p, "/")
	for i := range parts {
		q := filepath.Join(root, filepath.Join(parts[:i+1]...))
		st, e := os.Lstat(q)
		if os.IsNotExist(e) {
			return true
		}
		if e != nil {
			return false
		}
		if i < len(parts)-1 {
			if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return false
			}
		} else if !st.Mode().IsRegular() && st.Mode()&os.ModeSymlink == 0 {
			return false
		}
	}
	return true
}

func trackedStatus(run *runner, path, stage string, safe []string, excluded int) ([]byte, *Failure) {
	if len(safe) == 0 {
		return []byte{}, nil
	}
	args := []string{"--literal-pathspecs", "status", "--porcelain=v1", "-z", "--untracked-files=no", "--ignore-submodules=all", "--no-renames"}
	if excluded > 0 {
		args = append(append(args, "--"), safe...)
	}
	return run.git(path, stage, args...)
}
