package validators

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type Example struct {
	Name  string
	Age   int
	Valid bool
}

func Test_isZero(t *testing.T) {
	assert.True(t, isZero(Example{}))
}

func Test_isZero_Ptr(t *testing.T) {
	assert.True(t, isZero(&Example{}))
}

func Test_isZero_AllFields(t *testing.T) {
	assert.False(t, isZero(Example{Name: "John", Age: 25, Valid: true}))
}

func Test_isZero_Name(t *testing.T) {
	assert.False(t, isZero(Example{Name: "John"}))
}

func Test_isZero_Age(t *testing.T) {
	assert.False(t, isZero(Example{Age: 25}))
}

func Test_isZero_Valid(t *testing.T) {
	assert.False(t, isZero(Example{Valid: true}))
}
