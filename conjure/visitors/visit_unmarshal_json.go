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

package visitors

import (
	"go/token"

	"github.com/palantir/goastwriter/astgen"
	"github.com/palantir/goastwriter/decl"
	"github.com/palantir/goastwriter/expression"
	"github.com/palantir/goastwriter/statement"
	"github.com/pkg/errors"

	"github.com/palantir/conjure-go/v6/conjure-api/conjure/spec"
	"github.com/palantir/conjure-go/v6/conjure/transforms"
	"github.com/palantir/conjure-go/v6/conjure/types"
)

func VisitStructFieldsUnmarshalJSONMethodBody(receiverName string, fields []spec.FieldDefinition, info types.PkgInfo) ([]astgen.ASTStmt, error) {
	info.AddImports("unsafe", "github.com/tidwall/gjson")
	var body []astgen.ASTStmt

	// if !gjson.ValidBytes(data) { return errors.NewInvalidArgument() }
	body = append(body, &statement.If{
		Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("gjson", "ValidBytes", expression.VariableVal("data"))),
		Body: []astgen.ASTStmt{
			statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")), //TODO: include more helpful info (type name, invalid json) in error
		},
	})

	// value := gjson.ParseBytes(data)
	body = append(body, statement.NewAssignment(expression.VariableVal("value"), token.DEFINE,
		expression.NewCallFunction("gjson", "ParseBytes", expression.VariableVal("data"))))

	// if !value.IsObject() { return errors.NewInvalidArgument() }
	body = append(body, &statement.If{
		Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("value", "IsObject")),
		Body: []astgen.ASTStmt{
			statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")), //TODO: include more helpful info (type name, invalid json) in error
		},
	})

	// TODO: initialize all collections

	// var err error
	body = append(body, statement.NewDecl(decl.NewVar("err", expression.ErrorType)))

	var fieldCases []statement.CaseClause
	for _, field := range fields {
		selector := expression.NewSelector(expression.VariableVal(receiverName), transforms.ExportedFieldName(string(field.FieldName)))
		assignment, err := caseBodyAssignStructFieldToGJSONValue(selector, field.Type, info)
		if err != nil {
			return nil, err
		}
		fieldCases = append(fieldCases, statement.CaseClause{
			Exprs: []astgen.ASTExpr{expression.StringVal(field.FieldName)},
			Body:  assignment,
		})
	}

	// value.ForEach(func(key, value gjson.Result) bool { switch key.Str { ... } return err == nil }
	body = append(body, statement.NewExpression(expression.NewCallFunction("value", "ForEach",
		expression.NewFuncLit(
			expression.FuncType{
				Params: expression.FuncParams{{
					Names: []string{"key", "value"},
					Type:  "gjson.Result",
				}},
				ReturnTypes: []expression.Type{expression.BoolType},
			},
			&statement.Switch{
				Expression: expression.NewSelector(expression.VariableVal("key"), "Str"),
				Cases:      fieldCases,
			},
			statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)),
		))))

	// return err
	body = append(body, statement.NewReturn(expression.VariableVal("err")))

	return body, nil
}

func caseBodyAssignStructFieldToGJSONValue(selector astgen.ASTExpr, fieldType spec.Type, info types.PkgInfo) ([]astgen.ASTStmt, error) {
	typeProvider, err := NewConjureTypeProvider(fieldType)
	if err != nil {
		return nil, err
	}
	typer, err := typeProvider.ParseType(info)
	if err != nil {
		return nil, err
	}
	info.AddImports(typer.ImportPaths()...)

	visitor := &gjsonUnmarshalValueVisitor{
		info:     info,
		selector: selector,
		valueVar: "value",
	}
	if err := fieldType.Accept(visitor); err != nil {
		return nil, err
	}

	var stmts []astgen.ASTStmt
	if visitor.typeCheck != nil {
		stmts = append(stmts, visitor.typeCheck)
	}
	stmts = append(stmts, visitor.stmts...)
	return stmts, nil
}

type gjsonUnmarshalValueVisitor struct {
	// in
	info       types.PkgInfo
	selector   astgen.ASTExpr
	valueVar   string

	// out
	typeCheck  astgen.ASTStmt
	stmts      []astgen.ASTStmt
	returnsErr bool
}

func (v *gjsonUnmarshalValueVisitor) VisitPrimitive(t spec.PrimitiveType) error {
	switch t.Value() {
	case spec.PrimitiveType_ANY:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "JSON", "String", "Number", "True", "False"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewCallFunction(v.valueVar, "Value"),
		})
	case spec.PrimitiveType_STRING:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
		})
	case spec.PrimitiveType_INTEGER:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "Number"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewCallExpression(expression.IntType, expression.NewCallFunction(v.valueVar, "Int")),
		})
	case spec.PrimitiveType_DOUBLE:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "Number"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewSelector(expression.VariableVal(v.valueVar), "Float"),
		})
	case spec.PrimitiveType_BOOLEAN:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "False", "True"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewSelector(expression.VariableVal(v.valueVar), "Bool"),
		})
	case spec.PrimitiveType_BINARY:
		v.info.AddImports(types.BinaryPkg.ImportPaths()...)
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
			Tok: token.ASSIGN,
			// binary.Binary(value.Str).Bytes()
			RHS: expression.NewCallExpression(expression.NewSelector(
				expression.NewCallExpression(
					expression.Type(types.BinaryPkg.GoType(v.info)),
					expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
				),
				"Bytes")),
		})
	case spec.PrimitiveType_BEARERTOKEN, spec.PrimitiveType_DATETIME, spec.PrimitiveType_RID, spec.PrimitiveType_UUID:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, unmarshalTextValue(v.selector, v.valueVar))
	case spec.PrimitiveType_SAFELONG:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "Number"))
		v.stmts = append(v.stmts, unmarshalJSONValue(v.selector, v.valueVar))
	case spec.PrimitiveType_UNKNOWN:
		return errors.New("Unsupported primitive type " + t.String())
	default:
		return errors.New("Unsupported primitive type " + t.String())
	}
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitOptional(t spec.OptionalType) error {
	var innerStmts []astgen.ASTStmt

	valDecl, err := declVar("v", t.ItemType, v.info)
	if err != nil {
		return err
	}

	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: expression.VariableVal("v"),
		valueVar: v.valueVar,
	}
	if err := t.ItemType.Accept(innerVisitor); err != nil {
		return err
	}
	if innerVisitor.typeCheck != nil {
		innerStmts = append(innerStmts, innerVisitor.typeCheck)
	}
	innerStmts = append(innerStmts, valDecl)
	innerStmts = append(innerStmts, innerVisitor.stmts...)
	innerStmts = append(innerStmts, &statement.Assignment{
		LHS: []astgen.ASTExpr{v.selector},
		Tok: token.ASSIGN,
		RHS: expression.NewUnary(token.AND, expression.VariableVal("v")),
	})
	v.stmts = append(v.stmts, &statement.If{
		Cond: gjsonTypeCondition(v.valueVar, "Null"),
		Body: innerStmts,
	})
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitList(t spec.ListType) error {
	var innerStmts []astgen.ASTStmt

	valDecl, err := declVar("v", t.ItemType, v.info)
	if err != nil {
		return err
	}

	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: expression.VariableVal("v"),
		valueVar: "value",
	}
	if err := t.ItemType.Accept(innerVisitor); err != nil {
		return err
	}
	if innerVisitor.typeCheck != nil {
		innerStmts = append(innerStmts, innerVisitor.typeCheck)
	}
	innerStmts = append(innerStmts, valDecl)
	innerStmts = append(innerStmts, innerVisitor.stmts...)
	// x.List = append(x.List, v)
	innerStmts = append(innerStmts, &statement.Assignment{
		LHS: []astgen.ASTExpr{v.selector},
		Tok: token.ASSIGN,
		RHS: expression.NewCallExpression(expression.AppendBuiltIn, v.selector, expression.VariableVal("v")),
	})
	innerStmts = append(innerStmts, statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)))

	v.stmts = append(v.stmts,
		gjsonTypeCheck(expression.NewUnary(token.NOT, expression.NewCallFunction(v.valueVar, "IsArray"))),
		// value.ForEach(func(_, value gjson.Result) bool { innerStmts...; return err == nil }
		statement.NewExpression(expression.NewCallFunction(v.valueVar, "ForEach",
			expression.NewFuncLit(
				expression.FuncType{
					Params: expression.FuncParams{{
						Names: []string{"_", "value"},
						Type:  "gjson.Result",
					}},
					ReturnTypes: []expression.Type{expression.BoolType},
				},
				innerStmts...,
			),
		)),
	)
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitSet(t spec.SetType) error {
	return v.VisitList(spec.ListType{ItemType: t.ItemType})
}

func (v *gjsonUnmarshalValueVisitor) VisitMap(t spec.MapType) error {
	mapTyper, err := NewConjureTypeProviderTyper(spec.NewTypeFromMap(t), v.info)
	if err != nil {
		return err
	}

	var innerStmts []astgen.ASTStmt

	destKey, destVal := expression.VariableVal("destKey"), expression.VariableVal("destVal")

	keyDecl, err := declVar("destKey", t.KeyType, v.info)
	if err != nil {
		return err
	}

	keyVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: destKey,
		valueVar: "key",
	}
	if err := t.KeyType.Accept(keyVisitor); err != nil {
		return err
	}
	if keyVisitor.typeCheck != nil {
		innerStmts = append(innerStmts, keyVisitor.typeCheck)
	}
	innerStmts = append(innerStmts, keyDecl)
	innerStmts = append(innerStmts, keyVisitor.stmts...)

	valDecl, err := declVar("destVal", t.ValueType, v.info)
	if err != nil {
		return err
	}
	valVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: destVal,
		valueVar: "value",
	}
	if err := t.ValueType.Accept(valVisitor); err != nil {
		return err
	}
	if valVisitor.typeCheck != nil {
		innerStmts = append(innerStmts, valVisitor.typeCheck)
	}
	innerStmts = append(innerStmts, valDecl)
	innerStmts = append(innerStmts, valVisitor.stmts...)

	v.stmts = append(v.stmts,
		gjsonTypeCheck(expression.NewUnary(token.NOT, expression.NewCallFunction(v.valueVar, "IsObject"))),
		// if r.Field == nil { r.Field = make(map[k]v) }
		&statement.If{
			Cond: expression.NewBinary(v.selector, token.EQL, expression.Nil),
			Body: []astgen.ASTStmt{statement.NewAssignment(
				v.selector,
				token.ASSIGN,
				expression.NewCallExpression(expression.MakeBuiltIn, expression.Type(mapTyper.GoType(v.info))),
			)},
		},
		// value.ForEach(func(key, value gjson.Result) bool { innerStmts... ; return err == nil }
		statement.NewExpression(expression.NewCallFunction(v.valueVar, "ForEach",
			expression.NewFuncLit(
				expression.FuncType{
					Params: expression.FuncParams{{
						Names: []string{"key", "value"},
						Type:  "gjson.Result",
					}},
					ReturnTypes: []expression.Type{expression.BoolType},
				},
				append(innerStmts,
					statement.NewAssignment(expression.NewIndex(v.selector, destKey), token.ASSIGN, destVal),
					statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)),
				)...,
			),
		)),
	)
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitExternal(t spec.ExternalReference) error {
	v.info.AddImports("encoding/json")
	v.stmts = append(v.stmts, &statement.Assignment{
		LHS: []astgen.ASTExpr{expression.VariableVal("err")},
		Tok: token.ASSIGN,
		RHS: expression.NewCallFunction("json", "Unmarshal",
			expression.NewUnary(token.AND, v.selector),
			expression.NewSelector(expression.VariableVal(v.valueVar), "Raw")),
	})
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitReference(t spec.TypeName) error {
	typ, ok := v.info.CustomTypes().Get(TypeNameToTyperName(t))
	if !ok {
		return errors.Errorf("reference type not found %s", t.Name)
	}
	defVisitor := gjsonUnmarshalValueReferenceDefVisitor{
		info:     v.info,
		selector: v.selector,
		valueVar: v.valueVar,
		typer:    typ,
	}
	if err := typ.Def.Accept(&defVisitor); err != nil {
		return err
	}

	v.typeCheck = defVisitor.typeCheck
	v.stmts = append(v.stmts, defVisitor.stmts...)
	v.returnsErr = defVisitor.returnsErr
	return nil
}

type gjsonUnmarshalValueReferenceDefVisitor struct {
	// in
	info     types.PkgInfo
	selector astgen.ASTExpr
	valueVar string
	typer    types.Typer

	// out
	typeCheck  astgen.ASTStmt
	stmts      []astgen.ASTStmt
	returnsErr bool
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitAlias(def spec.AliasDefinition) error {
	aliasTypeProvider, err := NewConjureTypeProvider(def.Alias)
	if err != nil {
		return err
	}
	if aliasTypeProvider.IsSpecificType(IsString) {
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, statement.NewAssignment(v.selector, token.ASSIGN,
			expression.NewCallExpression(expression.Type(v.typer.GoType(v.info)), expression.NewSelector(expression.VariableVal(v.valueVar), "Str"))))
	} else if aliasTypeProvider.IsSpecificType(IsText) {
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, unmarshalTextValue(v.selector, v.valueVar))
	} else {
		v.stmts = append(v.stmts, unmarshalJSONValue(v.selector, v.valueVar))
	}
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitEnum(_ spec.EnumDefinition) error {
	v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
	v.stmts = append(v.stmts, unmarshalTextValue(v.selector, v.valueVar))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitObject(_ spec.ObjectDefinition) error {
	v.stmts = append(v.stmts, unmarshalJSONValue(v.selector, v.valueVar))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitUnion(_ spec.UnionDefinition) error {
	v.stmts = append(v.stmts, unmarshalJSONValue(v.selector, v.valueVar))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitUnknown(typeName string) error {
	return errors.Errorf("unknown type %q", typeName)
}

func (v *gjsonUnmarshalValueVisitor) VisitUnknown(typeName string) error {
	return errors.Errorf("unknown type %q", typeName)
}

func unmarshalTextValue(selector astgen.ASTExpr, valueVar string) astgen.ASTStmt {
	return &statement.Assignment{
		LHS: []astgen.ASTExpr{expression.VariableVal("err")},
		Tok: token.ASSIGN,
		RHS: expression.NewCallExpression(expression.NewSelector(selector, "UnmarshalText"),
			expression.NewCallExpression(expression.Type("[]byte"), expression.NewSelector(expression.VariableVal(valueVar), "Str"))),
	}
}

func declVar(varName string, typ spec.Type, info types.PkgInfo) (*statement.Decl, error) {
	valTyper, err := NewConjureTypeProviderTyper(typ, info)
	if err != nil {
		return nil, err
	}
	return statement.NewDecl(decl.NewVar(varName, expression.Type(valTyper.GoType(info)))), nil
}

func unmarshalJSONValue(selector astgen.ASTExpr, valueVar string) astgen.ASTStmt {
	return &statement.Assignment{
		LHS: []astgen.ASTExpr{expression.VariableVal("err")},
		Tok: token.ASSIGN,
		RHS: expression.NewCallExpression(expression.NewSelector(selector, "UnmarshalJSON"),
			expression.NewCallExpression(expression.Type("[]byte"), expression.NewSelector(expression.VariableVal(valueVar), "Raw"))),
	}
}

func gjsonTypeCheck(cond astgen.ASTExpr) astgen.ASTStmt {
	check := &statement.If{
		Cond: cond,
		Body: []astgen.ASTStmt{
			errEqualNewInvalidArgument(),
			statement.NewReturn(expression.VariableVal("false")),
		},
	}
	return check
}

func gjsonTypeCondition(valueVar string, typeNames ...string) astgen.ASTExpr {
	var cond astgen.ASTExpr
	for _, typeName := range typeNames {
		test := expression.NewBinary(expression.NewSelector(expression.VariableVal(valueVar), "Type"), token.NEQ, expression.NewSelector(expression.VariableVal("gjson"), typeName))
		if cond == nil {
			cond = test
		} else {
			cond = expression.NewBinary(cond, token.LAND, test)
		}
	}
	return cond
}

func ifNotGJSONValueTypeReturnInvalidArgument(cond astgen.ASTExpr, body []astgen.ASTStmt) *statement.If {
	return &statement.If{
		Cond: cond,
		Body: body,
		Else: errEqualNewInvalidArgument(),
	}
}

func errEqualNewInvalidArgument() *statement.Assignment {
	return statement.NewAssignment(
		expression.VariableVal("err"),
		token.ASSIGN,
		expression.NewCallFunction("errors", "NewInvalidArgument"),
	)
}
