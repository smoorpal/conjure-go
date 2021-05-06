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

package jsonencoding

import (
	"fmt"
	"go/token"

	"github.com/palantir/goastwriter/astgen"
	"github.com/palantir/goastwriter/decl"
	"github.com/palantir/goastwriter/expression"
	"github.com/palantir/goastwriter/statement"
	"github.com/pkg/errors"

	"github.com/palantir/conjure-go/v6/conjure-api/conjure/spec"
	"github.com/palantir/conjure-go/v6/conjure/types"
	"github.com/palantir/conjure-go/v6/conjure/visitors"
)

type JSONFieldDefinition struct {
	FieldSelector string
	JSONKey       string
	Type          spec.Type
}

func StructFieldsUnmarshalMethods(receiverName string, receiverType string, fields []JSONFieldDefinition, info types.PkgInfo) ([]astgen.ASTDecl, error) {
	info.AddImports("unsafe", "github.com/tidwall/gjson", "github.com/palantir/conjure-go-runtime/v2/conjure-go-contract/errors")
	var methods []astgen.ASTDecl

	methods = append(methods,
		&decl.Method{
			ReceiverName: receiverName,
			ReceiverType: expression.Type(receiverType).Pointer(),
			Function: decl.Function{
				Name:    "UnmarshalJSON",
				Comment: "UnmarshalJSON deserializes data, ignoring unrecognized keys.\nPrefer UnmarshalJSONString if data is already in string form to avoid an extra copy.",
				FuncType: expression.FuncType{
					Params:      expression.FuncParams{expression.NewFuncParam("data", expression.ByteSliceType)},
					ReturnTypes: []expression.Type{expression.ErrorType},
				},
				Body: []astgen.ASTStmt{
					// if !gjson.ValidBytes(data) { return errors.NewInvalidArgument() }
					&statement.If{
						Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("gjson", "ValidBytes", expression.VariableVal("data"))),
						Body: []astgen.ASTStmt{
							statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")),
						},
					},
					// return o.unmarshalGJSON(gjson.ParseBytes(data), false)
					statement.NewReturn(expression.NewCallFunction(receiverName, "unmarshalGJSON",
						expression.NewCallFunction("gjson", "ParseBytes", expression.VariableVal("data")),
						expression.VariableVal("false"))),
				},
			},
		},
		&decl.Method{
			ReceiverName: receiverName,
			ReceiverType: expression.Type(receiverType).Pointer(),
			Function: decl.Function{
				Name:    "UnmarshalJSONString",
				Comment: "UnmarshalJSONString deserializes data, ignoring unrecognized keys.",
				FuncType: expression.FuncType{
					Params:      expression.FuncParams{expression.NewFuncParam("data", expression.StringType)},
					ReturnTypes: []expression.Type{expression.ErrorType},
				},
				Body: []astgen.ASTStmt{
					// if !gjson.Valid(data) { return errors.NewInvalidArgument() }
					&statement.If{
						Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("gjson", "Valid", expression.VariableVal("data"))),
						Body: []astgen.ASTStmt{
							statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")),
						},
					},
					// return o.unmarshalGJSON(gjson.Parse(data), false)
					statement.NewReturn(expression.NewCallFunction(receiverName, "unmarshalGJSON",
						expression.NewCallFunction("gjson", "Parse", expression.VariableVal("data")),
						expression.VariableVal("false"))),
				},
			},
		},
		&decl.Method{
			ReceiverName: receiverName,
			ReceiverType: expression.Type(receiverType).Pointer(),
			Function: decl.Function{
				Name:    "UnmarshalJSONStrict",
				Comment: "UnmarshalJSONStrict deserializes data, rejecting unrecognized keys.\nPrefer UnmarshalJSONStringStrict if data is already in string form to avoid an extra copy.",
				FuncType: expression.FuncType{
					Params:      expression.FuncParams{expression.NewFuncParam("data", expression.ByteSliceType)},
					ReturnTypes: []expression.Type{expression.ErrorType},
				},
				Body: []astgen.ASTStmt{
					// if !gjson.ValidBytes(data) { return errors.NewInvalidArgument() }
					&statement.If{
						Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("gjson", "ValidBytes", expression.VariableVal("data"))),
						Body: []astgen.ASTStmt{
							statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")),
						},
					},
					// return o.unmarshalGJSON(gjson.ParseBytes(data), true)
					statement.NewReturn(expression.NewCallFunction(receiverName, "unmarshalGJSON",
						expression.NewCallFunction("gjson", "ParseBytes", expression.VariableVal("data")),
						expression.VariableVal("true"))),
				},
			},
		},
		&decl.Method{
			ReceiverName: receiverName,
			ReceiverType: expression.Type(receiverType).Pointer(),
			Function: decl.Function{
				Name:    "UnmarshalJSONStringStrict",
				Comment: "UnmarshalJSONStringStrict deserializes data, rejecting unrecognized keys.",
				FuncType: expression.FuncType{
					Params:      expression.FuncParams{expression.NewFuncParam("data", expression.StringType)},
					ReturnTypes: []expression.Type{expression.ErrorType},
				},
				Body: []astgen.ASTStmt{
					// if !gjson.Valid(data) { return errors.NewInvalidArgument() }
					&statement.If{
						Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("gjson", "Valid", expression.VariableVal("data"))),
						Body: []astgen.ASTStmt{
							statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")),
						},
					},
					// return o.unmarshalGJSON(gjson.Parse(data), false)
					statement.NewReturn(expression.NewCallFunction(receiverName, "unmarshalGJSON",
						expression.NewCallFunction("gjson", "Parse", expression.VariableVal("data")),
						expression.VariableVal("true"))),
				},
			},
		},
	)

	unmarshalGJSONBody, err := visitStructFieldsUnmarshalGJSONMethodBody(receiverName, fields, info)
	if err != nil {
		return nil, err
	}
	methods = append(methods, &decl.Method{
		ReceiverName: receiverName,
		ReceiverType: expression.Type(receiverType).Pointer(),
		Function: decl.Function{
			Name: "unmarshalGJSON",
			FuncType: expression.FuncType{
				Params: expression.FuncParams{
					expression.NewFuncParam("value", expression.Type("gjson.Result")),
					expression.NewFuncParam("strict", expression.BoolType),
				},
				ReturnTypes: []expression.Type{expression.ErrorType},
			},
			Body: unmarshalGJSONBody,
		},
	})

	return methods, nil
}

func visitStructFieldsUnmarshalGJSONMethodBody(receiverName string, fields []JSONFieldDefinition, info types.PkgInfo) ([]astgen.ASTStmt, error) {
	info.SetImports("wparams", "github.com/palantir/witchcraft-go-params")
	var body []astgen.ASTStmt

	// if !value.IsObject() { return errors.NewInvalidArgument() }
	body = append(body, &statement.If{
		Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("value", "IsObject")),
		Body: []astgen.ASTStmt{
			statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")), //TODO: include more helpful info (type name, invalid json) in error
		},
	})
	var fieldInits []astgen.ASTStmt
	var fieldCases []statement.CaseClause
	var fieldValidates []astgen.ASTStmt
	for _, field := range fields {
		selector := expression.NewSelector(expression.VariableVal(receiverName), field.FieldSelector)
		stmts, err := visitStructFieldsUnmarshalJSONMethodStmts(selector, field, info)
		if err != nil {
			return nil, err
		}
		fieldInits = append(fieldInits, stmts.Init...)
		fieldCases = append(fieldCases, statement.CaseClause{
			Exprs: []astgen.ASTExpr{expression.StringVal(field.JSONKey)},
			Body:  stmts.UnmarshalGJSON,
		})
		fieldValidates = append(fieldValidates, stmts.ValidateReqdField...)
	}
	unrecognizedFieldsVar := expression.VariableVal("unrecognizedFields")
	fieldCases = append(fieldCases, statement.CaseClause{
		Exprs: nil, // default case
		Body: []astgen.ASTStmt{&statement.If{
			Cond: expression.VariableVal("strict"),
			Body: []astgen.ASTStmt{
				statement.NewAssignment(unrecognizedFieldsVar, token.ASSIGN,
					expression.NewCallExpression(expression.AppendBuiltIn, unrecognizedFieldsVar, expression.VariableVal("key.String()"))),
			},
		}},
	})

	body = append(body, fieldInits...)

	// var unrecognizedFields []string
	body = append(body, statement.NewDecl(decl.NewVar("unrecognizedFields", "[]string")))
	// var err error
	body = append(body, statement.NewDecl(decl.NewVar("err", expression.ErrorType)))

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
			&statement.If{
				Cond: expression.NewBinary(
					expression.NewSelector(expression.VariableVal("value"), "Type"),
					token.EQL,
					expression.NewSelector(expression.VariableVal("gjson"), "Null"),
				),
				Body: []astgen.ASTStmt{
					statement.NewReturn(expression.VariableVal("true")),
				},
			},
			&statement.Switch{
				Expression: expression.NewSelector(expression.VariableVal("key"), "Str"),
				Cases:      fieldCases,
			},
			statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)),
		),
	)))
	// if err != nil { return err }
	body = append(body, &statement.If{
		Cond: expression.NewBinary(expression.VariableVal("err"), token.NEQ, expression.Nil),
		Body: []astgen.ASTStmt{statement.NewReturn(expression.VariableVal("err"))},
	})
	if len(fieldValidates) > 0 {
		missingFieldsVar := expression.VariableVal("missingFields")
		body = append(body, statement.NewDecl(decl.NewVar("missingFields", "[]string")))
		body = append(body, fieldValidates...)
		body = append(body, &statement.If{
			Cond: expression.NewBinary(
				expression.NewCallExpression(expression.LenBuiltIn, missingFieldsVar),
				token.GTR,
				expression.IntVal(0),
			),
			Body: []astgen.ASTStmt{statement.NewReturn(
				expression.NewCallFunction("errors", "NewInvalidArgument",
					expression.NewCallFunction("wparams", "NewSafeParam", expression.StringVal("missingFields"), missingFieldsVar),
				),
			)},
		})
	}
	body = append(body, &statement.If{
		Cond: expression.NewBinary(
			expression.VariableVal("strict"),
			token.LAND,
			expression.NewBinary(
				expression.NewCallExpression(expression.LenBuiltIn, unrecognizedFieldsVar),
				token.GTR,
				expression.IntVal(0),
			),
		),
		Body: []astgen.ASTStmt{statement.NewReturn(
			expression.NewCallFunction("errors", "NewInvalidArgument",
				expression.NewCallFunction("wparams", "NewSafeParam", expression.StringVal("unrecognizedFields"), unrecognizedFieldsVar),
			),
		)},
	})
	body = append(body, statement.NewReturn(expression.Nil))

	return body, nil
}

type structFieldsUnmarshalJSONMethodStmts struct {
	Init              []astgen.ASTStmt
	UnmarshalGJSON    []astgen.ASTStmt
	ValidateReqdField []astgen.ASTStmt
}

func visitStructFieldsUnmarshalJSONMethodStmts(selector astgen.ASTExpr, field JSONFieldDefinition, info types.PkgInfo) (structFieldsUnmarshalJSONMethodStmts, error) {
	result := structFieldsUnmarshalJSONMethodStmts{}

	typeProvider, err := visitors.NewConjureTypeProvider(field.Type)
	if err != nil {
		return result, err
	}
	typer, err := typeProvider.ParseType(info)
	if err != nil {
		return result, err
	}
	info.AddImports(typer.ImportPaths()...)

	collectionExpression, err := typeProvider.CollectionInitializationIfNeeded(info)
	if err != nil {
		return result, err
	}
	// If a field is not a collection or optional, it is required.
	requiredField := collectionExpression == nil && !typeProvider.IsSpecificType(visitors.IsOptional) // TODO(bmoylan) This does not handle aliases of optionals
	seenVar := "seen" + field.FieldSelector

	if requiredField {
		// Declare a 'var seenFieldName bool' which we will set to true inside the case statement.
		result.Init = append(result.Init, statement.NewDecl(decl.NewVar(seenVar, expression.BoolType)))
	}
	if collectionExpression != nil {
		result.Init = append(result.Init, statement.NewAssignment(selector, token.ASSIGN, collectionExpression))
	}

	visitor := &gjsonUnmarshalValueVisitor{
		info:     info,
		selector: selector,
		valueVar: "value",
	}
	if err := field.Type.Accept(visitor); err != nil {
		return result, err
	}
	if visitor.typeCheck != nil {
		result.UnmarshalGJSON = append(result.UnmarshalGJSON, visitor.typeCheck)
	}
	result.UnmarshalGJSON = append(result.UnmarshalGJSON, visitor.stmts...)

	if requiredField {
		result.UnmarshalGJSON = append(
			[]astgen.ASTStmt{statement.NewAssignment(expression.VariableVal(seenVar), token.ASSIGN, expression.VariableVal("true"))},
			result.UnmarshalGJSON...)

		result.ValidateReqdField = append(result.ValidateReqdField, &statement.If{
			Cond: expression.NewUnary(token.NOT, expression.VariableVal(seenVar)),
			Body: []astgen.ASTStmt{
				statement.NewAssignment(expression.VariableVal("missingFields"), token.ASSIGN,
					expression.NewCallExpression(expression.AppendBuiltIn, expression.VariableVal("missingFields"), expression.StringVal(field.JSONKey))),
			},
		})
	}

	return result, nil
}

type gjsonUnmarshalValueVisitor struct {
	// in
	info          types.PkgInfo
	selector      astgen.ASTExpr
	valueVar      string
	selectorToken token.Token
	isMapKey      bool
	nestDepth     int

	// out
	typeCheck astgen.ASTStmt
	stmts     []astgen.ASTStmt
}

func (v *gjsonUnmarshalValueVisitor) VisitPrimitive(t spec.PrimitiveType) error {
	switch t.Value() {
	case spec.PrimitiveType_ANY:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "JSON", "String", "Number", "True", "False"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallFunction(v.valueVar, "Value"),
		})
	case spec.PrimitiveType_STRING:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
		})
	case spec.PrimitiveType_INTEGER:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "Number"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallExpression(expression.IntType, expression.NewCallFunction(v.valueVar, "Int")),
		})
	case spec.PrimitiveType_DOUBLE:
		v.info.AddImports("math")
		assignDouble := func(rhs astgen.ASTExpr) astgen.ASTStmt {
			return &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector},
				Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
				RHS: rhs,
			}
		}
		v.stmts = append(v.stmts, &statement.Switch{
			Expression: expression.NewSelector(expression.VariableVal(v.valueVar), "Type"),
			Cases: []statement.CaseClause{
				{
					Exprs: []astgen.ASTExpr{expression.NewSelector(expression.VariableVal("gjson"), "Number")},
					Body:  []astgen.ASTStmt{assignDouble(expression.NewSelector(expression.VariableVal(v.valueVar), "Num"))},
				},
				{
					Exprs: []astgen.ASTExpr{expression.NewSelector(expression.VariableVal("gjson"), "String")},
					Body: []astgen.ASTStmt{&statement.Switch{
						Expression: expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
						Cases: []statement.CaseClause{
							{
								Exprs: []astgen.ASTExpr{expression.StringVal("NaN")},
								Body:  []astgen.ASTStmt{assignDouble(expression.NewCallFunction("math", "NaN"))},
							},
							{
								Exprs: []astgen.ASTExpr{expression.StringVal("Infinity")},
								Body:  []astgen.ASTStmt{assignDouble(expression.NewCallFunction("math", "Inf", expression.IntVal(1)))},
							},
							{
								Exprs: []astgen.ASTExpr{expression.StringVal("-Infinity")},
								Body:  []astgen.ASTStmt{assignDouble(expression.NewCallFunction("math", "Inf", expression.IntVal(-1)))},
							},
							{
								Exprs: nil, // default case
								Body:  []astgen.ASTStmt{errEqualNewInvalidArgument()},
							},
						},
					}},
				},
				{
					Exprs: nil, // default case
					Body:  []astgen.ASTStmt{errEqualNewInvalidArgument()},
				},
			},
		})

		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "Number"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewSelector(expression.VariableVal(v.valueVar), "Num"),
		})
	case spec.PrimitiveType_BOOLEAN:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "False", "True"))
		if v.isMapKey {
			v.stmts = append(v.stmts, &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector},
				Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
				RHS: expression.NewCallFunction("boolean", "Boolean", expression.NewCallFunction(v.valueVar, "Bool")),
			})
		} else {
			v.stmts = append(v.stmts, &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector},
				Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
				RHS: expression.NewCallFunction(v.valueVar, "Bool"),
			})
		}
	case spec.PrimitiveType_BINARY:
		v.info.AddImports(types.BinaryPkg.ImportPaths()...)
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))

		binaryObj := expression.NewCallExpression(
			expression.Type(types.BinaryPkg.GoType(v.info)),
			expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
		)
		if v.isMapKey {
			// v = binary.Binary(value.Str)
			v.stmts = append(v.stmts, &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector},
				Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
				RHS: binaryObj,
			})
		} else {
			// v, err = binary.Binary(value.Str).Bytes()
			v.stmts = append(v.stmts, &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
				Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
				RHS: expression.NewCallExpression(expression.NewSelector(binaryObj, "Bytes")),
			})
		}
	case spec.PrimitiveType_BEARERTOKEN:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallFunction("bearertoken", "Token",
				expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
			),
		})
	case spec.PrimitiveType_DATETIME:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallFunction("datetime", "ParseDateTime",
				expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
			),
		})
	case spec.PrimitiveType_RID:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallFunction("rid", "ParseRID",
				expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
			),
		})
	case spec.PrimitiveType_SAFELONG:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "Number"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallFunction("safelong", "NewSafeLong",
				expression.NewCallFunction(v.valueVar, "Int")),
		})
	case spec.PrimitiveType_UUID:
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
			Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
			RHS: expression.NewCallFunction("uuid", "ParseUUID",
				expression.NewSelector(expression.VariableVal(v.valueVar), "Str"),
			),
		})
	case spec.PrimitiveType_UNKNOWN:
		return errors.New("Unsupported primitive type " + t.String())
	default:
		return errors.New("Unsupported primitive type " + t.String())
	}
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitOptional(t spec.OptionalType) error {
	var innerStmts []astgen.ASTStmt

	valVar := expression.VariableVal(tmpVarName("optionalValue", v.nestDepth))
	valDecl, err := declVar(string(valVar), t.ItemType, v.info)
	if err != nil {
		return err
	}

	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  valVar,
		valueVar:  v.valueVar,
		nestDepth: v.nestDepth + 1,
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
		Tok: tokenOrDefault(v.selectorToken, token.ASSIGN),
		RHS: expression.NewUnary(token.AND, valVar),
	})
	v.stmts = append(v.stmts, &statement.If{
		Cond: gjsonTypeCondition(v.valueVar, "Null"),
		Body: innerStmts,
	})
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitList(t spec.ListType) error {

	var innerStmts []astgen.ASTStmt

	valVar := expression.VariableVal(tmpVarName("listElement", v.nestDepth))
	valDecl, err := declVar(string(valVar), t.ItemType, v.info)
	if err != nil {
		return err
	}
	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  valVar,
		valueVar:  "value",
		nestDepth: v.nestDepth + 1,
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
		RHS: expression.NewCallExpression(expression.AppendBuiltIn, v.selector, valVar),
	})
	innerStmts = append(innerStmts, statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)))

	v.typeCheck = gjsonTypeCheck(expression.NewUnary(token.NOT, expression.NewCallFunction(v.valueVar, "IsArray")))
	// value.ForEach(func(_, value gjson.Result) bool { innerStmts...; return err == nil }
	v.stmts = append(v.stmts, statement.NewExpression(expression.NewCallFunction(v.valueVar, "ForEach",
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
	)))
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitSet(t spec.SetType) error {
	return v.VisitList(spec.ListType{ItemType: t.ItemType})
}

func (v *gjsonUnmarshalValueVisitor) VisitMap(t spec.MapType) error {
	mapTypeProvider, err := visitors.NewConjureTypeProvider(spec.NewTypeFromMap(t))
	if err != nil {
		return err
	}
	keyTypeProvider, err := visitors.NewConjureTypeProvider(t.KeyType)
	if err != nil {
		return err
	}
	keyTyper, err := keyTypeProvider.ParseType(v.info)
	if err != nil {
		return err
	}
	// Use binary.Binary for map keys since []byte is invalid in go maps.
	if keyTypeProvider.IsSpecificType(visitors.IsBinary) {
		keyTyper = types.BinaryPkg
	}
	// Use boolean.Boolean for map keys since conjure boolean keys are serialized as strings
	if keyTypeProvider.IsSpecificType(visitors.IsBoolean) {
		keyTyper = types.BooleanPkg
	}

	var innerStmts []astgen.ASTStmt

	keyVar := expression.VariableVal(tmpVarName("mapKey", v.nestDepth))
	valVar := expression.VariableVal(tmpVarName("mapVal", v.nestDepth))

	keyVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  keyVar,
		valueVar:  "key",
		isMapKey:  true,
		nestDepth: v.nestDepth + 1,
	}
	if err := t.KeyType.Accept(keyVisitor); err != nil {
		return err
	}
	valDecl, err := declVar(string(valVar), t.ValueType, v.info)
	if err != nil {
		return err
	}
	valVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  valVar,
		valueVar:  "value",
		nestDepth: v.nestDepth + 1,
	}
	if err := t.ValueType.Accept(valVisitor); err != nil {
		return err
	}

	if keyVisitor.typeCheck != nil {
		innerStmts = append(innerStmts, keyVisitor.typeCheck)
	}
	if valVisitor.typeCheck != nil {
		innerStmts = append(innerStmts, valVisitor.typeCheck)
	}
	keyDecl := statement.NewDecl(decl.NewVar(string(keyVar), expression.Type(keyTyper.GoType(v.info))))
	innerStmts = append(innerStmts, keyDecl)
	innerStmts = append(innerStmts, keyVisitor.stmts...)
	innerStmts = append(innerStmts, valDecl)
	innerStmts = append(innerStmts, valVisitor.stmts...)

	v.typeCheck = gjsonTypeCheck(expression.NewUnary(token.NOT, expression.NewCallFunction(v.valueVar, "IsObject")))

	collectionInit, err := mapTypeProvider.CollectionInitializationIfNeeded(v.info)
	if err != nil {
		return err
	}
	variableInit := statement.NewAssignment(v.selector, tokenOrDefault(v.selectorToken, token.ASSIGN), collectionInit)

	if v.selectorToken == token.DEFINE {
		// v1 := make(map[k]v, 0)
		v.stmts = append(v.stmts, variableInit)
	} else {
		// if r.Field == nil { r.Field = make(map[k]v) }
		v.stmts = append(v.stmts, &statement.If{
			Cond: expression.NewBinary(v.selector, token.EQL, expression.Nil),
			Body: []astgen.ASTStmt{variableInit},
		})
	}

	v.stmts = append(v.stmts,
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
					statement.NewAssignment(expression.NewIndex(v.selector, keyVar), token.ASSIGN, valVar),
					statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)),
				)...,
			),
		)),
	)
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitExternal(_ spec.ExternalReference) error {
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
	typ, ok := v.info.CustomTypes().Get(visitors.TypeNameToTyperName(t))
	if !ok {
		return errors.Errorf("reference type not found %s", t.Name)
	}
	defVisitor := gjsonUnmarshalValueReferenceDefVisitor{
		info:          v.info,
		selector:      v.selector,
		valueVar:      v.valueVar,
		typer:         typ,
		selectorToken: v.selectorToken,
		nestDepth:     v.nestDepth,
	}
	if err := typ.Def.Accept(&defVisitor); err != nil {
		return err
	}

	v.typeCheck = defVisitor.typeCheck
	v.stmts = append(v.stmts, defVisitor.stmts...)
	return nil
}

type gjsonUnmarshalValueReferenceDefVisitor struct {
	// in
	info          types.PkgInfo
	selector      astgen.ASTExpr
	valueVar      string
	typer         types.Typer
	selectorToken token.Token
	nestDepth     int

	// out
	typeCheck astgen.ASTStmt
	stmts     []astgen.ASTStmt
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitAlias(def spec.AliasDefinition) error {
	aliasTypeProvider, err := visitors.NewConjureTypeProvider(def.Alias)
	if err != nil {
		return err
	}
	if aliasTypeProvider.IsSpecificType(visitors.IsString) {
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, statement.NewAssignment(v.selector, tokenOrDefault(v.selectorToken, token.ASSIGN),
			expression.NewCallExpression(expression.Type(v.typer.GoType(v.info)), expression.NewSelector(expression.VariableVal(v.valueVar), "Str"))))
	} else if aliasTypeProvider.IsSpecificType(visitors.IsText) {
		v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
		v.stmts = append(v.stmts, unmarshalTextValue(v.selector, v.valueVar))
	} else {
		v.stmts = append(v.stmts, unmarshalJSONStringValue(v.selector, v.valueVar))
	}
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitEnum(_ spec.EnumDefinition) error {
	v.typeCheck = gjsonTypeCheck(gjsonTypeCondition(v.valueVar, "String"))
	v.stmts = append(v.stmts, unmarshalTextValue(v.selector, v.valueVar))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitObject(def spec.ObjectDefinition) error {
	if len(def.Fields) > 0 {
		v.stmts = append(v.stmts, unmarshalJSONStringValue(v.selector, v.valueVar))
	}
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitUnion(_ spec.UnionDefinition) error {
	v.stmts = append(v.stmts, unmarshalJSONStringValue(v.selector, v.valueVar))
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
	valTyper, err := visitors.NewConjureTypeProviderTyper(typ, info)
	if err != nil {
		return nil, err
	}
	return statement.NewDecl(decl.NewVar(varName, expression.Type(valTyper.GoType(info)))), nil
}

func unmarshalJSONStringValue(selector astgen.ASTExpr, valueVar string) astgen.ASTStmt {
	return &statement.If{
		Cond: expression.VariableVal("strict"),
		Body: []astgen.ASTStmt{
			&statement.Assignment{
				LHS: []astgen.ASTExpr{expression.VariableVal("err")},
				Tok: token.ASSIGN,
				RHS: expression.NewCallExpression(expression.NewSelector(selector, "UnmarshalJSONStringStrict"),
					expression.NewSelector(expression.VariableVal(valueVar), "Raw")),
			},
		},
		Else: &statement.Assignment{
			LHS: []astgen.ASTExpr{expression.VariableVal("err")},
			Tok: token.ASSIGN,
			RHS: expression.NewCallExpression(expression.NewSelector(selector, "UnmarshalJSONString"),
				expression.NewSelector(expression.VariableVal(valueVar), "Raw")),
		},
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

func errEqualNewInvalidArgument() *statement.Assignment {
	return statement.NewAssignment(
		expression.VariableVal("err"),
		token.ASSIGN,
		expression.NewCallFunction("errors", "NewInvalidArgument"),
	)
}

func tokenOrDefault(t, d token.Token) token.Token {
	if t == 0 {
		return d
	}
	return t
}

func tmpVarName(base string, depth int) string {
	if depth == 0 {
		return base
	}
	return fmt.Sprintf("%s%d", base, depth)
}
