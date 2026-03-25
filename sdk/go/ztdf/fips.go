package ztdf

import (
	"github.com/stratiumdata/go-sdk/internal/fipsruntime"
)

func isFIPSModeEnabled() bool {
	return fipsruntime.Enabled()
}
