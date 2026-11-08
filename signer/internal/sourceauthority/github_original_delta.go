package sourceauthority

// Delta sizes are little-endian base-128 integers, independent of the pack
// object's size encoding. Read at most ten bytes and reject uint64 overflow.
func originalGitDeltaSize(data []byte) (uint64, []byte, bool) {
	var size uint64
	for shift := uint(0); shift < 64 && len(data) > 0; shift += 7 {
		b := data[0]
		data = data[1:]
		if uint64(b&127) > (^uint64(0) >> shift) {
			return 0, nil, false
		}
		size |= uint64(b&127) << shift
		if b&128 == 0 {
			return size, data, true
		}
	}
	return 0, nil, false
}

// Apply only an in-pack commit delta. Instructions, input/output storage,
// copies and identity parsing all debit the existing phase before work. Both
// the instruction stream and reconstructed commit fit the installed commit
// ceiling; the pack's existing count ceiling bounds chain length. No fallback
// Git process, thin-pack base acquisition or new allowance is introduced.
func originalGitApplyDelta(p *acquisitionPhase, base, data []byte, commitMax int) ([]byte, error) {
	if commitMax <= 0 || len(data) > commitMax || len(base) > commitMax {
		return nil, unavailable("github_git_commit_size")
	}
	baseSize, data, ok := originalGitDeltaSize(data)
	if !ok || baseSize != uint64(len(base)) {
		return nil, unavailable("github_git_delta_base_size")
	}
	size, data, ok := originalGitDeltaSize(data)
	if !ok || size == 0 || size > uint64(commitMax) {
		return nil, unavailable("github_git_delta_result_size")
	}
	if err := p.originalGitCharge(int64(size)*64 + 65536); err != nil {
		return nil, err
	}
	out := make([]byte, 0, int(size))
	for len(data) > 0 {
		if err := p.originalGitCharge(0); err != nil {
			return nil, err
		}
		cmd := data[0]
		data = data[1:]
		if cmd&128 == 0 {
			n := int(cmd)
			if n == 0 || n > len(data) || n > int(size)-len(out) {
				return nil, unavailable("github_git_delta_instruction")
			}
			out = append(out, data[:n]...)
			data = data[n:]
			continue
		}
		var offset, count uint64
		for bit := uint(0); bit < 7; bit++ {
			if cmd&(1<<bit) == 0 {
				continue
			}
			if len(data) == 0 {
				return nil, unavailable("github_git_delta_instruction")
			}
			if bit < 4 {
				offset |= uint64(data[0]) << (bit * 8)
			} else {
				count |= uint64(data[0]) << ((bit - 4) * 8)
			}
			data = data[1:]
		}
		if count == 0 {
			count = 65536
		}
		if offset > uint64(len(base)) || count > uint64(len(base))-offset || count > size-uint64(len(out)) {
			return nil, unavailable("github_git_delta_copy")
		}
		out = append(out, base[int(offset):int(offset+count)]...)
	}
	if uint64(len(out)) != size {
		return nil, unavailable("github_git_delta_result_size")
	}
	return out, nil
}
