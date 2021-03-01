package conjure_test

import (
	"testing"

	"github.com/palantir/conjure-go/v6/cmd"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	err := cmd.Generate("conjure-api-4.14.1.conjure.json", "")
	require.NoError(t, err)
}
