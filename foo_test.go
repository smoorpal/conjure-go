// Copyright (c) 2021 Palantir Technologies. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	werror "github.com/palantir/witchcraft-go-error"
	"github.com/stretchr/testify/require"

	"github.com/palantir/conjure-go/v6/conjure-api/conjure/spec"
)

func BenchmarkUnmarshal(b *testing.B) {
	b.Run("empty IR", func(b *testing.B) {
		irBytes := []byte(`{"version":1}`)
		benchIR(b, irBytes)
	})
	b.Run("small IR", func(b *testing.B) {
		irBytes := []byte(`{"version":1,"errors":[],"types":[{"type":"object","object":{"typeName":{"name":"AliasDefinition","package":"com.palantir.conjure.spec"},"fields":[{"fieldName":"typeName","type":{"type":"reference","reference":{"name":"TypeName","package":"com.palantir.conjure.spec"}}}]}}],"services":[],"extensions":{"recommended-product-dependencies":[]}}`)
		benchIR(b, irBytes)
	})
	b.Run("large IR", func(b *testing.B) {
		irBytes, err := ioutil.ReadFile("conjure-api/conjure-api-4.14.1.conjure.json")
		require.NoError(b, err)
		benchIR(b, irBytes)
	})
}

func benchIR(b *testing.B, inputBytes []byte) {
	inputString := string(inputBytes)

	b.Run("json.Unmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var conjureDefinition spec.ConjureDefinition
			if err := json.Unmarshal(inputBytes, &conjureDefinition); err != nil {
				b.Fatal(werror.GenerateErrorString(err, true))
			}
		}
		b.ReportAllocs()
	})
	b.Run("bytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var conjureDefinition spec.ConjureDefinition
			if err := conjureDefinition.UnmarshalJSON(inputBytes); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})
	b.Run("string", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var conjureDefinition spec.ConjureDefinition
			if err := conjureDefinition.UnmarshalJSONString(inputString); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})
	b.Run("string alloc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			inputString := string(inputBytes)
			var conjureDefinition spec.ConjureDefinition
			if err := conjureDefinition.UnmarshalJSONString(inputString); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})
}

func TestFoo1(t *testing.T) {
	var val string
	err := json.Unmarshal([]byte(`"hello"`), &val)
	require.NoError(t, err)
	t.Log(val)
}

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
