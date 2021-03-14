package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFoo(t *testing.T) {
	var val myType
	err := val.UnmarshalJSON([]byte("hello"))
	require.NoError(t, err)
	t.Log(val)
}

type myType struct {
	Field *string
}

func (o *myType) UnmarshalJSON(b []byte) error {
	//if o == nil {
	//	o = &myType{}
	//}
	*o.Field = string(b)
	return nil
}
