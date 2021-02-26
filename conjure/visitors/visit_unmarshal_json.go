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
		info:      info,
		selector:  selector,
		assignTok: token.ASSIGN,
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
	assignTok  token.Token
	postAssign []astgen.ASTStmt

	// out
	stmts      []astgen.ASTStmt
	returnsErr bool
}

func (v *gjsonUnmarshalValueVisitor) VisitPrimitive(t spec.PrimitiveType) error {
	castExpr := func(typer types.Typer) func(expr astgen.ASTExpr) astgen.ASTExpr {
		return func(expr astgen.ASTExpr) astgen.ASTExpr {
			return expression.NewCallExpression(expression.Type(typer.GoType(v.info)), expr)
		}
	}
	switch t.Value() {
	case spec.PrimitiveType_ANY:
		v.assignParseValue("Value()", []string{"Json", "String", "Number", "True", "False"}, nil, false)
	case spec.PrimitiveType_STRING:
		v.assignParseValue("Str", []string{"String"}, nil, false)
	case spec.PrimitiveType_INTEGER:
		v.assignParseValue("Int()", []string{"Number"}, castExpr(types.Integer), false)
	case spec.PrimitiveType_DOUBLE:
		v.assignParseValue("Float", []string{"Number"}, nil, false)
	case spec.PrimitiveType_BOOLEAN:
		v.assignParseValue("Bool", []string{"False", "True"}, nil, false)
	case spec.PrimitiveType_BEARERTOKEN:
		v.assignParseValue("Str", []string{"String"}, castExpr(types.Bearertoken), false)
	case spec.PrimitiveType_DATETIME:
		v.assignParseValue("Str", []string{"String"}, castExpr(types.ParseDateTime), true)
	case spec.PrimitiveType_RID:
		v.assignParseValue("Str", []string{"String"}, castExpr(types.ParseRID), true)
	case spec.PrimitiveType_SAFELONG:
		v.assignParseValue("Int()", []string{"Number"}, castExpr(types.NewSafeLong), true)
	case spec.PrimitiveType_UUID:
		v.assignParseValue("Str", []string{"String"}, castExpr(types.ParseUUID), true)
	case spec.PrimitiveType_BINARY:
		v.info.AddImports(types.Base64Encoding.ImportPaths()...)
		decodeB64 := func(expr astgen.ASTExpr) astgen.ASTExpr {
			return expression.NewCallExpression(expression.NewSelector(expression.Type(types.Base64Encoding.GoType(v.info)), "DecodeString"), expr)
		}
		v.assignParseValue("Str", []string{"String"}, decodeB64, true)
	case spec.PrimitiveType_UNKNOWN:
		return errors.New("Unsupported primitive type " + t.String())
	default:
		return errors.New("Unsupported primitive type " + t.String())
	}
	return nil
}
func (v *gjsonUnmarshalValueVisitor) VisitOptional(t spec.OptionalType) error {
	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  expression.VariableVal("v"),
		assignTok: token.DEFINE,
		postAssign: []astgen.ASTStmt{&statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: token.ASSIGN,
			RHS: expression.NewUnary(token.AND, expression.VariableVal("v")),
		}},
	}
	if err := t.ItemType.Accept(innerVisitor); err != nil {
		return err
	}
	v.stmts = append(v.stmts, &statement.If{
		Cond: gjsonNotTypeCondition("Null"),
		Body: innerVisitor.stmts,
	})
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitList(t spec.ListType) error {
	innerVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  expression.VariableVal("v"),
		assignTok: token.DEFINE,
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
					append(innerVisitor.stmts, statement.NewReturn(
						expression.NewBinary(expression.VariableVal("err"), token.EQL, expression.Nil),
					))...,
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
	keyTyper, err := NewConjureTypeProviderTyper(t.KeyType, v.info)
	if err != nil {
		return err
	}
	valTyper, err := NewConjureTypeProviderTyper(t.ValueType, v.info)
	if err != nil {
		return err
	}
	var innerStmts []astgen.ASTStmt

	destKey, destVal := expression.VariableVal("destKey"), expression.VariableVal("destVal")

	innerStmts = append(innerStmts, statement.NewDecl(decl.NewVar("destKey", expression.Type(keyTyper.GoType(v.info)))))
	keyVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  destKey,
		assignTok: token.ASSIGN,
	}
	if err := t.KeyType.Accept(keyVisitor); err != nil {
		return err
	}
	innerStmts = append(innerStmts, keyVisitor.stmts...)

	innerStmts = append(innerStmts, statement.NewDecl(decl.NewVar("destVal", expression.Type(valTyper.GoType(v.info)))))
	valVisitor := &gjsonUnmarshalValueVisitor{
		info:      v.info,
		selector:  destVal,
		assignTok: token.ASSIGN,
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

func (v *gjsonUnmarshalValueVisitor) VisitReference(t spec.TypeName) error {
	typ, ok := v.info.CustomTypes().Get(t.Name)
	if !ok {
		return errors.Errorf("reference type not found %s", t.Name)
	}
	typ.Def.Accept()

	panic("implement me")
	return nil
}



func (v *gjsonUnmarshalValueVisitor) VisitExternal(t spec.ExternalReference) error {
	panic("implement me")
	return nil
}

func (v *gjsonUnmarshalValueVisitor) VisitUnknown(typeName string) error {
	return errors.Errorf("unknown type %q", typeName)
}

func (v *gjsonUnmarshalValueVisitor) assignParseValue(valueField string, gjsonTypes []string, parse func(astgen.ASTExpr) astgen.ASTExpr, returnsErr bool) {
	ifStmt := &statement.If{
		Cond: gjsonTypeCondition(gjsonTypes...),
		Body: []astgen.ASTStmt{},
		Else: errEqualNewInvalidArgument(),
	}
	switch {
	case returnsErr:
		if v.assignTok == token.DEFINE {
			ifStmt.Body = append(ifStmt.Body, &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("parseErr")},
				Tok: token.DEFINE,
				RHS: parse(expression.NewSelector(expression.VariableVal("value"), valueField)),
			})
			ifStmt.Body = append(ifStmt.Body, statement.NewAssignment(expression.VariableVal("err"), token.ASSIGN, expression.VariableVal("parseErr")))
		} else {
			ifStmt.Body = append(ifStmt.Body, &statement.Assignment{
				LHS: []astgen.ASTExpr{v.selector, expression.VariableVal("err")},
				Tok: token.ASSIGN,
				RHS: parse(expression.NewSelector(expression.VariableVal("value"), valueField)),
			})
		}
	case parse == nil:
		ifStmt.Body = append(ifStmt.Body, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: v.assignTok,
			RHS: expression.NewSelector(expression.VariableVal("value"), valueField),
		})
	default:
		ifStmt.Body = append(ifStmt.Body, &statement.Assignment{
			LHS: []astgen.ASTExpr{v.selector},
			Tok: v.assignTok,
			RHS: parse(expression.NewSelector(expression.VariableVal("value"), valueField)),
		})
	}
	ifStmt.Body = append(ifStmt.Body, v.postAssign...)
	v.stmts = append(v.stmts, ifStmt)
}

func gjsonTypeCondition(typeNames ...string) astgen.ASTExpr {
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

func gjsonNotTypeCondition(typeNames ...string) astgen.ASTExpr {
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
