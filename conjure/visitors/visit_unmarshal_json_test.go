package visitors

import (
	"testing"

	"github.com/palantir/goastwriter"
	"github.com/palantir/goastwriter/decl"
	"github.com/palantir/goastwriter/expression"
	"github.com/stretchr/testify/assert"

	"github.com/palantir/conjure-go/v6/conjure-api/conjure/spec"
	"github.com/palantir/conjure-go/v6/conjure/types"
)

func TestStructFieldJSONMethods(t *testing.T) {

	stmts, err := VisitStructFieldsUnmarshalJSONMethodBody("x", []spec.FieldDefinition{
		{
			FieldName: "fieldString",
			Type:      spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_STRING)),
		},
		{
			FieldName: "fieldInt",
			Type:      spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_INTEGER)),
		},
		{
			FieldName: "fieldDatetime",
			Type:      spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_DATETIME)),
		},
		{
			FieldName: "fieldSafelong",
			Type:      spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_SAFELONG)),
		},
		{
			FieldName: "fieldUUID",
			Type:      spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_UUID)),
		},
		{
			FieldName: "fieldBinary",
			Type:      spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_BINARY)),
		},
		{
			FieldName: "fieldOptionalString",
			Type:      spec.NewTypeFromOptional(spec.OptionalType{ItemType: spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_STRING))}),
		},
		{
			FieldName: "fieldListString",
			Type:      spec.NewTypeFromList(spec.ListType{ItemType: spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_STRING))}),
		},
		//{
		//	FieldName: "fieldListInteger",
		//	Type:      spec.NewTypeFromList(spec.ListType{ItemType: spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_INTEGER))}),
		//},
		{
			FieldName: "fieldListDatetime",
			Type:      spec.NewTypeFromList(spec.ListType{ItemType: spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_DATETIME))}),
		},
		{
			FieldName: "fieldMapStringString",
			Type: spec.NewTypeFromMap(spec.MapType{
				KeyType:   spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_STRING)),
				ValueType: spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_STRING)),
			}),
		},
		{
			FieldName: "fieldMapDatetimeSafelong",
			Type: spec.NewTypeFromMap(spec.MapType{
				KeyType:   spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_DATETIME)),
				ValueType: spec.NewTypeFromPrimitive(spec.New_PrimitiveType(spec.PrimitiveType_SAFELONG)),
			}),
		},
	}, types.NewPkgInfo("main", types.NewCustomConjureTypes()))

	out, err := goastwriter.Write("main", &decl.Var{
		Name:  "Stmt",
		Type:  "",
		Value: expression.NewFuncLit(expression.FuncType{}, stmts...),
	})
	assert.NoError(t, err)
	t.Log(string(out))
}
