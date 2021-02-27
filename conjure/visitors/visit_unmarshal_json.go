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

	// 	str := *(*string)(unsafe.Pointer(&data))
	body = append(body, statement.NewAssignment(expression.VariableVal("str"), token.DEFINE,
		expression.NewCallExpression(
			expression.NewCallExpression(expression.VariableVal("*"), expression.StringType.Pointer()),
			expression.NewCallFunction("unsafe", "Pointer",
				expression.NewUnary(token.AND, expression.VariableVal("data")),
			),
		),
	))
	// if !gjson.Valid(str) { return errors.NewInvalidArgument() }
	body = append(body, &statement.If{
		Cond: expression.NewUnary(token.NOT, expression.NewCallFunction("gjson", "Valid", expression.VariableVal("str"))),
		Body: []astgen.ASTStmt{
			statement.NewReturn(expression.NewCallFunction("errors", "NewInvalidArgument")), //TODO: include more helpful info (type name, invalid json) in error
		},
	})

	// value := gjson.Parse(data)
	body = append(body, statement.NewAssignment(expression.VariableVal("value"), token.DEFINE,
		expression.NewCallFunction("gjson", "Parse", expression.VariableVal("str"))))

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

	fieldCases := make([]statement.CaseClause, len(fields))
	for i, field := range fields {
		selector := expression.NewSelector(expression.VariableVal(receiverName), transforms.ExportedFieldName(string(field.FieldName)))
		assignment, err := caseBodyAssignStructFieldToGJSONValue(selector, field.Type, info)
		if err != nil {
			return nil, err
		}
		fieldCases[i] = statement.CaseClause{
			Exprs: []astgen.ASTExpr{expression.StringVal(field.FieldName)},
			Body:  assignment,
		}
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
	}
	if err := fieldType.Accept(visitor); err != nil {
		return nil, err
	}
	return visitor.stmts, nil
}

type gjsonUnmarshalValueVisitor struct {
	// in
	info       types.PkgInfo
	selector   astgen.ASTExpr
	postAssign []astgen.ASTStmt

	// out
	stmts      []astgen.ASTStmt
	returnsErr bool
}

func (v *gjsonUnmarshalValueVisitor) VisitPrimitive(t spec.PrimitiveType) error {
	switch t.Value() {
	case spec.PrimitiveType_ANY:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("JSON", "String", "Number", "True", "False")))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewCallFunction("value", "Value"),
		})
	case spec.PrimitiveType_STRING:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("String")))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewSelector(expression.VariableVal("value"), "Str"),
		})
	case spec.PrimitiveType_INTEGER:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("Number")))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewCallExpression(expression.IntType, expression.NewCallFunction("value", "Int")),
		})
	case spec.PrimitiveType_DOUBLE:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("Number")))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewSelector(expression.VariableVal("value"), "Float"),
		})
	case spec.PrimitiveType_BOOLEAN:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("False", "True")))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewSelector(expression.VariableVal("value"), "Bool"),
		})
	case spec.PrimitiveType_BINARY:
		v.info.AddImports(types.BinaryPkg.ImportPaths()...)
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("String")))
		v.stmts = append(v.stmts, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
			Tok: token.ASSIGN,
			// binary.Binary(value.Str).Bytes()
			RHS: expression.NewCallExpression(expression.NewSelector(
				expression.NewCallExpression(
					expression.Type(types.BinaryPkg.GoType(v.info)),
					expression.NewSelector(expression.VariableVal("value"), "Str"),
				),
				"Bytes")),
		})
	case spec.PrimitiveType_BEARERTOKEN, spec.PrimitiveType_DATETIME, spec.PrimitiveType_RID, spec.PrimitiveType_UUID:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("String")))
		v.stmts = append(v.stmts, unmarshalTextValue(v.selector))
	case spec.PrimitiveType_SAFELONG:
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("Number")))
		v.stmts = append(v.stmts, unmarshalJSONValue(v.selector))
	case spec.PrimitiveType_UNKNOWN:
		return errors.New("Unsupported primitive type " + t.String())
	default:
		return errors.New("Unsupported primitive type " + t.String())
	}
	v.stmts = append(v.stmts, v.postAssign...)
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitOptional(t spec.OptionalType) error {
	var innerStmts []astgen.ASTStmt

	valDecl, err := declVar("v", t.ItemType, v.info)
	if err != nil {
		return err
	}
	innerStmts = append(innerStmts, valDecl)

	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: expression.VariableVal("v"),
		postAssign: []astgen.ASTStmt{&statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewUnary(token.AND, expression.VariableVal("v")),
		}},
	}
	if err := t.ItemType.Accept(innerVisitor); err != nil {
		return err
	}
	innerStmts = append(innerStmts, innerVisitor.stmts...)
	v.stmts = append(v.stmts, &statement.If{
		Cond: gjsonNotTypeCondition("Null"),
		Body: innerVisitor.stmts,
	})
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitList(t spec.ListType) error {
	var innerStmts []astgen.ASTStmt

	valDecl, err := declVar("v", t.ItemType, v.info)
	if err != nil {
		return err
	}
	innerStmts = append(innerStmts, valDecl)

	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: expression.VariableVal("v"),
		// x.List = append(x.List, v)
		postAssign: []astgen.ASTStmt{&statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewCallExpression(expression.AppendBuiltIn, v.selector, expression.VariableVal("v")),
		}},
	}
	if err := t.ItemType.Accept(innerVisitor); err != nil {
		return err
	}
	innerStmts = append(innerStmts, innerVisitor.stmts...)
	innerStmts = append(innerStmts, statement.NewReturn(expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil)))

	v.stmts = append(v.stmts, ifNotGJSONValueTypeReturnInvalidArgument(
		expression.NewCallFunction("value", "IsArray"),
		[]astgen.ASTStmt{
			// value.ForEach(func(_, value gjson.Result) bool { innerStmts...; return err == nil }
			statement.NewExpression(expression.NewCallFunction("value", "ForEach",
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
		},
	))
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
	innerStmts = append(innerStmts, keyDecl)

	keyVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: destKey,
	}
	if err := t.KeyType.Accept(keyVisitor); err != nil {
		return err
	}
	innerStmts = append(innerStmts, keyVisitor.stmts...)

	valDecl, err := declVar("destVal", t.ValueType, v.info)
	if err != nil {
		return err
	}
	innerStmts = append(innerStmts, valDecl)
	valVisitor := &gjsonUnmarshalValueVisitor{
		info:     v.info,
		selector: destVal,
	}
	if err := t.ValueType.Accept(valVisitor); err != nil {
		return err
	}
	innerStmts = append(innerStmts, valVisitor.stmts...)

	v.stmts = append(v.stmts, ifNotGJSONValueTypeReturnInvalidArgument(
		expression.NewCallFunction("value", "IsObject"),
		// value.ForEach(func(key, value gjson.Result) bool { innerStmts... ; return err == nil }
		[]astgen.ASTStmt{
			// if r.Field == nil { r.Field = make(map[k]v) }
			&statement.If{
				Cond: expression.NewBinary(v.selector, token.EQL, expression.Nil),
				Body: []astgen.ASTStmt{statement.NewAssignment(
					v.selector,
					token.ASSIGN,
					expression.NewCallExpression(expression.MakeBuiltIn, expression.Type(mapTyper.GoType(v.info))),
				)},
			},
			statement.NewExpression(expression.NewCallFunction("value", "ForEach",
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
		},
	))
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitExternal(t spec.ExternalReference) error {
	v.info.AddImports("encoding/json")
	v.stmts = append(v.stmts, &statement.Assignment{
		LHS: []astgen.ASTExpr{expression.VariableVal("err")},
		Tok: token.ASSIGN,
		RHS: expression.NewCallFunction("json", "Unmarshal",
			expression.NewUnary(token.AND, v.selector),
			expression.NewSelector(expression.VariableVal("value"), "Raw")),
	})
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitReference(t spec.TypeName) error {
	typ, ok := v.info.CustomTypes().Get(t.Name)
	if !ok {
		return errors.Errorf("reference type not found %s", t.Name)
	}
	defVisitor := gjsonUnmarshalValueReferenceDefVisitor{}
	if err := typ.Def.Accept(&defVisitor); err != nil {
		return err
	}
	v.stmts = defVisitor.stmts
	v.returnsErr = defVisitor.returnsErr
	return nil
}

type gjsonUnmarshalValueReferenceDefVisitor struct {
	// in
	info     types.PkgInfo
	selector astgen.ASTExpr

	// out
	stmts      []astgen.ASTStmt
	returnsErr bool
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitAlias(def spec.AliasDefinition) error {
	aliasTypeProvider, err := NewConjureTypeProvider(def.Alias)
	if err != nil {
		return err
	}
	if aliasTypeProvider.IsSpecificType(IsText) {
		v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("String")))
		v.stmts = append(v.stmts, unmarshalTextValue(v.selector))
	} else {
		v.stmts = append(v.stmts, unmarshalJSONValue(v.selector))
	}
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitEnum(_ spec.EnumDefinition) error {
	v.stmts = append(v.stmts, gjsonTypeCheck(gjsonTypeCondition("String")))
	v.stmts = append(v.stmts, unmarshalTextValue(v.selector))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitObject(_ spec.ObjectDefinition) error {
	v.stmts = append(v.stmts, unmarshalJSONValue(v.selector))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitUnion(_ spec.UnionDefinition) error {
	v.stmts = append(v.stmts, unmarshalJSONValue(v.selector))
	return nil
}

func (v *gjsonUnmarshalValueReferenceDefVisitor) VisitUnknown(typeName string) error {
	return errors.Errorf("unknown type %q", typeName)
}

func (v *gjsonUnmarshalValueVisitor) VisitUnknown(typeName string) error {
	return errors.Errorf("unknown type %q", typeName)
}

func unmarshalTextValue(selector astgen.ASTExpr) astgen.ASTStmt {
	return &statement.Assignment{
		LHS: []astgen.ASTExpr{expression.VariableVal("err")},
		Tok: token.ASSIGN,
		RHS: expression.NewCallExpression(expression.NewSelector(selector, "UnmarshalText"),
			expression.NewCallExpression(expression.Type("[]byte"), expression.NewSelector(expression.VariableVal("value"), "Str"))),
	}
}

func declVar(varName string, typ spec.Type, info types.PkgInfo) (*statement.Decl, error) {
	valTyper, err := NewConjureTypeProviderTyper(typ, info)
	if err != nil {
		return nil, err
	}
	return statement.NewDecl(decl.NewVar(varName, expression.Type(valTyper.GoType(info)))), nil
}

func unmarshalJSONValue(selector astgen.ASTExpr) astgen.ASTStmt {
	return &statement.Assignment{
		LHS: []astgen.ASTExpr{expression.VariableVal("err")},
		Tok: token.ASSIGN,
		RHS: expression.NewCallExpression(expression.NewSelector(selector, "UnmarshalJSON"),
			expression.NewCallExpression(expression.Type("[]byte"), expression.NewSelector(expression.VariableVal("value"), "Raw"))),
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

func gjsonTypeCondition(typeNames ...string) astgen.ASTExpr {
	var cond astgen.ASTExpr
	for _, typeName := range typeNames {
		test := expression.NewBinary(expression.NewSelector(expression.VariableVal("value"), "Type"), token.NEQ, expression.NewSelector(expression.VariableVal("gjson"), typeName))
		if cond == nil {
			cond = test
		} else {
			cond = expression.NewBinary(cond, token.LAND, test)
		}
	}
	return cond
}

func gjsonNotTypeCondition(typeNames ...string) astgen.ASTExpr {
	var cond astgen.ASTExpr
	for _, typeName := range typeNames {
		test := expression.NewBinary(expression.NewSelector(expression.VariableVal("value"), "Type"), token.EQL, expression.NewSelector(expression.VariableVal("gjson"), typeName))
		if cond == nil {
			cond = test
		} else {
			cond = expression.NewBinary(cond, token.LOR, test)
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
