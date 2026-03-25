package ztdf

import (
	"stratium/pkg/security/fipsruntime"
)

func isFIPSModeEnabled() bool {
	return fipsruntime.Enabled()
}
