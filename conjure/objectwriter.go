// Copyright (c) 2018 Palantir Technologies. All rights reserved.
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

package conjure

import (
	"fmt"
	"go/token"

	"github.com/palantir/goastwriter/astgen"
	"github.com/palantir/goastwriter/decl"
	"github.com/palantir/goastwriter/expression"
	"github.com/palantir/goastwriter/statement"
	"github.com/pkg/errors"

	"github.com/palantir/conjure-go/v6/conjure-api/conjure/spec"
	"github.com/palantir/conjure-go/v6/conjure/transforms"
	"github.com/palantir/conjure-go/v6/conjure/types"
	"github.com/palantir/conjure-go/v6/conjure/visitors"
	"github.com/palantir/conjure-go/v6/conjure/visitors/jsonencoding"
)

func astForObject(objectDefinition spec.ObjectDefinition, info types.PkgInfo) ([]astgen.ASTDecl, error) {
	if err := addImportPathsFromFields(objectDefinition.Fields, info); err != nil {
		return nil, err
	}

	var structFields []*expression.StructField

	for _, fieldDefinition := range objectDefinition.Fields {
		conjureTypeProvider, err := visitors.NewConjureTypeProvider(fieldDefinition.Type)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create type provider for field %s for object %s",
				fieldDefinition.FieldName,
				objectDefinition.TypeName.Name)
		}
		typer, err := conjureTypeProvider.ParseType(info)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse type field %s for object %s",
				fieldDefinition.FieldName,
				objectDefinition.TypeName.Name)
		}
		info.AddImports(typer.ImportPaths()...)

		structFields = append(structFields, &expression.StructField{
			Name:    transforms.ExportedFieldName(string(fieldDefinition.FieldName)),
			Type:    expression.Type(typer.GoType(info)),
			Tag:     fmt.Sprintf("json:%q", fieldDefinition.FieldName),
			Comment: transforms.Documentation(fieldDefinition.Docs),
		})
	}

	decls := []astgen.ASTDecl{
		decl.NewStruct(objectDefinition.TypeName.Name, structFields, transforms.Documentation(objectDefinition.Docs)),
	}

	if len(objectDefinition.Fields) > 0 {
		jsonMarshalDecl, err := astForStructJSONMarshal(objectDefinition, info)
		if err != nil {
			return nil, err
		}
		decls = append(decls, jsonMarshalDecl)

		jsonUnmarshalDecl, err := astForStructJSONUnmarshal(objectDefinition, info)
		if err != nil {
			return nil, err
		}
		decls = append(decls, jsonUnmarshalDecl...)

		decls = append(decls, newMarshalYAMLMethod(objReceiverName, objectDefinition.TypeName.Name, info))
		decls = append(decls, newUnmarshalYAMLMethod(objReceiverName, objectDefinition.TypeName.Name, info))
	}

	return decls, nil
}

const (
	objReceiverName = "o"
)

func astForStructJSONMarshal(objectDefinition spec.ObjectDefinition, info types.PkgInfo) (astgen.ASTDecl, error) {
	var body []astgen.ASTStmt
	marshalInit, err := structMarshalInitDecls(objectDefinition, objReceiverName, info)
	if err != nil {
		return nil, err
	}
	body = append(body, marshalInit...)

	aliasTypeName := objectDefinition.TypeName.Name + "Alias"
	body = append(body, statement.NewDecl(
		&decl.Alias{
			Name: aliasTypeName,
			Type: expression.Type(objectDefinition.TypeName.Name),
		},
	))

	info.AddImports(types.SafeJSONMarshal.ImportPaths()...)
	body = append(body, statement.NewReturn(
		&expression.CallExpression{
			Function: expression.Type(types.SafeJSONMarshal.GoType(info)),
			Args: []astgen.ASTExpr{
				&expression.CallExpression{
					Function: expression.VariableVal(aliasTypeName),
					Args: []astgen.ASTExpr{
						expression.VariableVal(objReceiverName),
					},
				},
			},
		},
	))

	return newMarshalJSONMethod(objReceiverName, objectDefinition.TypeName.Name, body...), nil
}

func astForStructJSONUnmarshal(objectDefinition spec.ObjectDefinition, info types.PkgInfo) ([]astgen.ASTDecl, error) {
	//var body []astgen.ASTStmt
	//aliasTypeName := objectDefinition.TypeName.Name + "Alias"
	//body = append(body, statement.NewDecl(
	//	&decl.Alias{
	//		Name: aliasTypeName,
	//		Type: expression.Type(objectDefinition.TypeName.Name),
	//	},
	//))
	//
	//rawVarName := fmt.Sprint("raw", objectDefinition.TypeName.Name)
	//body = append(body, statement.NewDecl(
	//	decl.NewVar(rawVarName, expression.Type(aliasTypeName)),
	//))
	//
	//info.AddImports(types.SafeJSONUnmarshal.ImportPaths()...)
	//body = append(body, ifErrNotNilReturnErrStatement("err",
	//	statement.NewAssignment(
	//		expression.VariableVal("err"),
	//		token.DEFINE,
	//		&expression.CallExpression{
	//			Function: expression.Type(types.SafeJSONUnmarshal.GoType(info)),
	//			Args: []astgen.ASTExpr{
	//				expression.VariableVal(dataVarName),
	//				expression.NewUnary(token.AND, expression.VariableVal(rawVarName)),
	//			},
	//		},
	//	),
	//))
	//
	//marshalInit, err := structMarshalInitDecls(objectDefinition, rawVarName, info)
	//if err != nil {
	//	return nil, err
	//}
	//body = append(body, marshalInit...)
	//
	//body = append(body, statement.NewAssignment(
	//	expression.NewStar(expression.VariableVal(objReceiverName)),
	//	token.ASSIGN,
	//	expression.NewCallExpression(expression.VariableVal(objectDefinition.TypeName.Name), expression.VariableVal(rawVarName)),
	//))
	//
	//body = append(body, statement.NewReturn(expression.Nil))

	//body, err := visitors.VisitStructFieldsUnmarshalJSONMethodBody(objReceiverName, objectDefinition.Fields, info)
	//if err != nil {
	//	return nil, err
	//}
	//return newUnmarshalJSONMethod(objReceiverName, objectDefinition.TypeName.Name, body...), nil

	var fields []jsonencoding.JSONFieldDefinition
	for _, field := range objectDefinition.Fields {
		fields = append(fields, jsonencoding.JSONFieldDefinition{
			FieldSelector: transforms.ExportedFieldName(string(field.FieldName)),
			JSONKey:       string(field.FieldName),
			Type:          field.Type,
		})
	}
	return jsonencoding.StructFieldsUnmarshalMethods(objReceiverName, objectDefinition.TypeName.Name, fields, info)
}

func structMarshalInitDecls(objectDefinition spec.ObjectDefinition, variableVal string, info types.PkgInfo) ([]astgen.ASTStmt, error) {
	var decls []astgen.ASTStmt
	for _, fieldDefinition := range objectDefinition.Fields {
		conjureTypeProvider, err := visitors.NewConjureTypeProvider(fieldDefinition.Type)
		if err != nil {
			return nil, err
		}

		collectionExpression, err := conjureTypeProvider.CollectionInitializationIfNeeded(info)
		if err != nil {
			return nil, err
		}

		if collectionExpression != nil {
			currFieldName := string(fieldDefinition.FieldName)
			decls = append(decls, &statement.If{
				Cond: expression.NewBinary(
					expression.NewSelector(expression.VariableVal(variableVal), transforms.ExportedFieldName(currFieldName)),
					token.EQL,
					expression.Nil,
				),
				Body: []astgen.ASTStmt{
					statement.NewAssignment(
						expression.NewSelector(expression.VariableVal(variableVal), transforms.ExportedFieldName(currFieldName)),
						token.ASSIGN,
						collectionExpression,
					),
				},
			})
		}
	}
	return decls, nil
}
