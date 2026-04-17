// Package iac — ARM template expression interpreter.
//
// ARM templates wrap expressions in [square brackets]. Example:
//
//	"name": "[concat('kv-', parameters('env'))]"
//	"storageEndpoint": "[reference(parameters('storageId')).primaryEndpoints.blob]"
//	"count":           "[add(parameters('minCount'), 1)]"
//
// This package evaluates those expressions to concrete values before
// the translator maps the template to an AzureSnapshot. Two classes
// of functions exist:
//
//   * Pure functions — parameters, variables, concat, format, if, length,
//     array/string/numeric helpers, JSON/base64 helpers, resourceId.
//     These resolve statically from the template's parameters / variables
//     blocks and literal inputs. ARGUS implements 40+ of them.
//
//   * Runtime functions — reference, listKeys, list*, environment,
//     subscription(), resourceGroup(), deployment(). These require
//     deployment-time state we don't have at scan time. They evaluate
//     to the sentinel `*armOpaque` value, which the interpreter then
//     converts to a marker string when embedded in another expression.
//     Rules that match on a specific string value won't match an
//     opaque marker, which is the correct behaviour: we neither
//     confirm nor deny the rule's predicate for the expression.
//
// The interpreter is intentionally a hand-written recursive-descent
// parser over a simple tokenizer. ARM's expression grammar is small
// (literals, strings, identifiers, dotted property access, bracket
// indexing, function calls) — a hand-written parser is easier to
// audit than pulling in a full expression library.
package iac

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// opaqueMarker is the string rendering used when a runtime-only
// function is evaluated at scan time. Anywhere this string appears in
// a resource's translated shape, downstream rules should interpret it
// as "value not known at scan time" rather than treating it as a
// literal. Choosing a distinctive prefix makes grep-based audit easy.
const opaqueMarker = "<<ARGUS_OPAQUE:"

// IsARMExpression reports whether the string is an ARM expression —
// the [literal-bracket-wrapped] form. A value like "[foo]" is an
// expression; "foo" is a literal; and "[[foo]]" is an escaped literal
// that represents the string "[foo]" (ARM's own escape convention).
func IsARMExpression(s string) bool {
	if len(s) < 2 {
		return false
	}
	return s[0] == '[' && s[len(s)-1] == ']' && !(len(s) >= 4 && s[:2] == "[[" && s[len(s)-2:] == "]]")
}

// ARMExprContext is the evaluation context: the parameters and
// variables blocks from the template. Both are map[string]interface{}
// — ARM allows parameters and variables to be any JSON value, not
// just scalars.
type ARMExprContext struct {
	Parameters map[string]interface{}
	Variables  map[string]interface{}
}

// ResolveARMValue takes any JSON value from an ARM template and
// recursively resolves any string that is an ARM expression. Objects
// and arrays are walked; non-string scalars are returned unchanged.
// String values not wrapped in brackets are returned as-is (no escape
// processing beyond the "[[" → "[" convention handled by
// unescapeLiteralBracket).
func ResolveARMValue(val interface{}, ctx *ARMExprContext) interface{} {
	switch v := val.(type) {
	case string:
		return resolveARMString(v, ctx)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, sub := range v {
			out[k] = ResolveARMValue(sub, ctx)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, sub := range v {
			out[i] = ResolveARMValue(sub, ctx)
		}
		return out
	}
	return val
}

// resolveARMString evaluates an ARM-expression string if it is one,
// otherwise returns the literal string with the ARM "[[" → "[" escape
// convention honoured. Evaluation failures return the original
// unresolved string so rules that would match on the literal form
// still have something to compare against.
func resolveARMString(s string, ctx *ARMExprContext) interface{} {
	if len(s) >= 4 && s[:2] == "[[" && s[len(s)-2:] == "]]" {
		// Escaped literal: "[[foo]]" means the string "[foo]".
		return "[" + s[2:len(s)-2] + "]"
	}
	if !IsARMExpression(s) {
		return s
	}
	// Strip the outer brackets and parse.
	inner := s[1 : len(s)-1]
	val, err := EvaluateExpression(inner, ctx)
	if err != nil {
		return s // preserve original on parse/eval error
	}
	return val
}

// EvaluateExpression parses and evaluates a bracket-stripped ARM
// expression string. Exported mainly for tests; most callers should
// use ResolveARMValue.
func EvaluateExpression(src string, ctx *ARMExprContext) (interface{}, error) {
	p := newExprParser(src)
	node, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.src) && !p.atEnd() {
		return nil, fmt.Errorf("unexpected trailing input at %d: %q", p.pos, p.src[p.pos:])
	}
	if ctx == nil {
		ctx = &ARMExprContext{}
	}
	return node.eval(ctx)
}

// ---------------------------------------------------------------------
// AST nodes
// ---------------------------------------------------------------------

type exprNode interface {
	eval(ctx *ARMExprContext) (interface{}, error)
}

type literalNode struct{ v interface{} }

func (n *literalNode) eval(_ *ARMExprContext) (interface{}, error) { return n.v, nil }

type callNode struct {
	name string
	args []exprNode
}

// propertyNode is dotted access: foo.bar — or bracket index: foo[0].
// path elements are either string keys (dotted) or int indices (bracket).
type propertyNode struct {
	receiver exprNode
	path     []interface{} // string or int
}

func (n *propertyNode) eval(ctx *ARMExprContext) (interface{}, error) {
	base, err := n.receiver.eval(ctx)
	if err != nil {
		return nil, err
	}
	for _, step := range n.path {
		if base == nil {
			return nil, nil
		}
		// Opaque values stay opaque when indexed.
		if s, ok := base.(string); ok && strings.HasPrefix(s, opaqueMarker) {
			return base, nil
		}
		switch k := step.(type) {
		case string:
			m, ok := base.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("cannot access property %q on non-object", k)
			}
			base = m[k]
		case int:
			a, ok := base.([]interface{})
			if !ok {
				return nil, fmt.Errorf("cannot index non-array with [%d]", k)
			}
			if k < 0 || k >= len(a) {
				return nil, nil
			}
			base = a[k]
		}
	}
	return base, nil
}

func (n *callNode) eval(ctx *ARMExprContext) (interface{}, error) {
	fn, ok := armFunctions[strings.ToLower(n.name)]
	if !ok {
		return nil, fmt.Errorf("unknown ARM function %q", n.name)
	}
	argVals := make([]interface{}, len(n.args))
	for i, a := range n.args {
		v, err := a.eval(ctx)
		if err != nil {
			return nil, err
		}
		argVals[i] = v
	}
	return fn(ctx, argVals)
}

// ---------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------

type exprParser struct {
	src string
	pos int
}

func newExprParser(src string) *exprParser {
	return &exprParser{src: src}
}

func (p *exprParser) atEnd() bool {
	p.skipWS()
	return p.pos >= len(p.src)
}

func (p *exprParser) skipWS() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t' || p.src[p.pos] == '\n' || p.src[p.pos] == '\r') {
		p.pos++
	}
}

// parseExpression returns a single expression node (literal, call, or
// property access). ARM's expression grammar has no operators outside
// function calls, so expressions reduce to:
//
//	expr := primary ( '.' ident | '[' expr ']' )*
//	primary := literal | call | '(' expr ')'
//	call := ident '(' [ expr (',' expr)* ] ')'
func (p *exprParser) parseExpression() (exprNode, error) {
	base, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	// Dotted/bracket chains.
	for {
		p.skipWS()
		if p.pos >= len(p.src) {
			break
		}
		switch p.src[p.pos] {
		case '.':
			p.pos++
			name, err := p.parseIdent()
			if err != nil {
				return nil, err
			}
			base = propertyChainAppend(base, name)
		case '[':
			p.pos++
			idx, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			p.skipWS()
			if p.pos >= len(p.src) || p.src[p.pos] != ']' {
				return nil, fmt.Errorf("expected ']' at %d", p.pos)
			}
			p.pos++
			base = propertyChainAppendExpr(base, idx)
		default:
			return base, nil
		}
	}
	return base, nil
}

// propertyChainAppend extends a node's property chain with a string key.
// If base is already a propertyNode the key appends to its path;
// otherwise a new propertyNode wraps the base.
func propertyChainAppend(base exprNode, key string) exprNode {
	if pn, ok := base.(*propertyNode); ok {
		pn.path = append(pn.path, key)
		return pn
	}
	return &propertyNode{receiver: base, path: []interface{}{key}}
}

// propertyChainAppendExpr extends with a bracket-indexed expression.
// If the index is a constant int or string, it's embedded directly;
// otherwise we wrap via a small runtime indexer node.
func propertyChainAppendExpr(base exprNode, idx exprNode) exprNode {
	if lit, ok := idx.(*literalNode); ok {
		var step interface{}
		switch v := lit.v.(type) {
		case int:
			step = v
		case float64:
			step = int(v)
		case string:
			step = v
		}
		if step != nil {
			if pn, ok := base.(*propertyNode); ok {
				pn.path = append(pn.path, step)
				return pn
			}
			return &propertyNode{receiver: base, path: []interface{}{step}}
		}
	}
	return &runtimeIndexNode{receiver: base, idx: idx}
}

type runtimeIndexNode struct {
	receiver exprNode
	idx      exprNode
}

func (n *runtimeIndexNode) eval(ctx *ARMExprContext) (interface{}, error) {
	base, err := n.receiver.eval(ctx)
	if err != nil {
		return nil, err
	}
	key, err := n.idx.eval(ctx)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case string:
		if m, ok := base.(map[string]interface{}); ok {
			return m[k], nil
		}
	case float64:
		if a, ok := base.([]interface{}); ok {
			i := int(k)
			if i < 0 || i >= len(a) {
				return nil, nil
			}
			return a[i], nil
		}
	case int:
		if a, ok := base.([]interface{}); ok {
			if k < 0 || k >= len(a) {
				return nil, nil
			}
			return a[k], nil
		}
	}
	return nil, nil
}

func (p *exprParser) parsePrimary() (exprNode, error) {
	p.skipWS()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	c := p.src[p.pos]
	switch {
	case c == '\'':
		return p.parseStringLiteral()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumberLiteral()
	case c == '(':
		p.pos++
		node, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return nil, fmt.Errorf("expected ')' at %d", p.pos)
		}
		p.pos++
		return node, nil
	case isIdentStart(c):
		name, err := p.parseIdent()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		// Bare identifiers "true" / "false" / "null" are boolean /
		// null literals per ARM. Everything else must be followed by
		// a '(' — ARM has no bare variables.
		switch strings.ToLower(name) {
		case "true":
			return &literalNode{v: true}, nil
		case "false":
			return &literalNode{v: false}, nil
		case "null":
			return &literalNode{v: nil}, nil
		}
		if p.pos >= len(p.src) || p.src[p.pos] != '(' {
			return nil, fmt.Errorf("expected '(' after identifier %q at %d", name, p.pos)
		}
		p.pos++
		args := []exprNode{}
		p.skipWS()
		if p.pos < len(p.src) && p.src[p.pos] == ')' {
			p.pos++
			return &callNode{name: name, args: args}, nil
		}
		for {
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
			p.skipWS()
			if p.pos >= len(p.src) {
				return nil, fmt.Errorf("unterminated arg list")
			}
			if p.src[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.src[p.pos] == ')' {
				p.pos++
				return &callNode{name: name, args: args}, nil
			}
			return nil, fmt.Errorf("expected ',' or ')' at %d, got %q", p.pos, string(p.src[p.pos]))
		}
	}
	return nil, fmt.Errorf("unexpected character %q at %d", string(c), p.pos)
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func (p *exprParser) parseIdent() (string, error) {
	p.skipWS()
	if p.pos >= len(p.src) || !isIdentStart(p.src[p.pos]) {
		return "", fmt.Errorf("expected identifier at %d", p.pos)
	}
	start := p.pos
	for p.pos < len(p.src) && isIdentChar(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos], nil
}

// parseStringLiteral reads a single-quoted string. ARM strings escape
// the single quote by doubling it ("it''s").
func (p *exprParser) parseStringLiteral() (exprNode, error) {
	if p.src[p.pos] != '\'' {
		return nil, fmt.Errorf("expected quote at %d", p.pos)
	}
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\'' {
			if p.pos+1 < len(p.src) && p.src[p.pos+1] == '\'' {
				// escaped
				b.WriteByte('\'')
				p.pos += 2
				continue
			}
			p.pos++
			return &literalNode{v: b.String()}, nil
		}
		b.WriteByte(c)
		p.pos++
	}
	return nil, fmt.Errorf("unterminated string literal")
}

func (p *exprParser) parseNumberLiteral() (exprNode, error) {
	start := p.pos
	if p.src[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.src) && (p.src[p.pos] >= '0' && p.src[p.pos] <= '9') {
		p.pos++
	}
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		p.pos++
		for p.pos < len(p.src) && (p.src[p.pos] >= '0' && p.src[p.pos] <= '9') {
			p.pos++
		}
	}
	raw := p.src[start:p.pos]
	if strings.Contains(raw, ".") {
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, err
		}
		return &literalNode{v: f}, nil
	}
	i, err := strconv.Atoi(raw)
	if err != nil {
		return nil, err
	}
	return &literalNode{v: i}, nil
}

// ---------------------------------------------------------------------
// Built-in function table
// ---------------------------------------------------------------------

// armFn is the signature every ARM template function implements.
// Implementations receive already-evaluated argument values; they
// never see unevaluated AST.
type armFn func(ctx *ARMExprContext, args []interface{}) (interface{}, error)

// armFunctions holds every supported ARM template function, keyed by
// lower-case name. Functions are grouped below by category for
// maintainability.
var armFunctions = map[string]armFn{
	// Deployment
	"parameters": fnParameters,
	"variables":  fnVariables,
	"coalesce":   fnCoalesce,
	"if":         fnIf,
	"equals":     fnEquals,
	"and":        fnAnd,
	"or":         fnOr,
	"not":        fnNot,
	"bool":       fnBool,
	"empty":      fnEmpty,

	// Arithmetic
	"add": fnAdd, "sub": fnSub, "mul": fnMul, "div": fnDiv, "mod": fnMod,
	"min": fnMin, "max": fnMax,
	"int":   fnInt,
	"float": fnFloat,

	// String
	"concat":     fnConcat,
	"format":     fnFormat,
	"length":     fnLength,
	"substring":  fnSubstring,
	"tolower":    fnToLower,
	"toupper":    fnToUpper,
	"trim":       fnTrim,
	"padleft":    fnPadLeft,
	"replace":    fnReplace,
	"split":      fnSplit,
	"startswith": fnStartsWith,
	"endswith":   fnEndsWith,
	"contains":   fnContains,
	"indexof":    fnIndexOf,
	"string":     fnString,
	"uri":        fnURI,
	"uricomponent":       fnURIComponent,
	"uricomponenttostring": fnURIComponentToString,
	"base64":           fnBase64,
	"base64tostring":   fnBase64ToString,
	"base64tojson":     fnBase64ToJSON,
	"datauri":          fnDataURI,
	"datauritostring":  fnDataURIToString,

	// Array / object
	"array":     fnArray,
	"createarray": fnCreateArray,
	"first":     fnFirst,
	"last":      fnLast,
	"skip":      fnSkip,
	"take":      fnTake,
	"union":     fnUnion,
	"intersection": fnIntersection,
	"range":     fnRange,
	"createobject": fnCreateObject,
	"json":      fnJSON,

	// Resource / scope
	"resourceid":       fnResourceID,
	"subscriptionresourceid": fnResourceID,
	"tenantresourceid": fnResourceID,
	"extensionresourceid": fnResourceID,

	// Runtime-only — return opaque markers
	"reference":      fnOpaque("reference"),
	"listkeys":       fnOpaque("listKeys"),
	"list":           fnOpaque("list"),
	"listsecrets":    fnOpaque("listSecrets"),
	"listaccountsas": fnOpaque("listAccountSas"),
	"listservicesas": fnOpaque("listServiceSas"),
	"environment":    fnOpaque("environment"),
	"subscription":   fnOpaque("subscription"),
	"resourcegroup":  fnOpaque("resourceGroup"),
	"deployment":     fnOpaque("deployment"),
	"providers":      fnOpaque("providers"),
	"pickzones":      fnOpaque("pickZones"),
	"managementgroup": fnOpaque("managementGroup"),
	"guid":           fnGUID, // deterministic based on seed args — OK to implement
	"uniquestring":   fnUniqueString, // same
	"newguid":        fnOpaque("newGuid"),
	"utcnow":         fnOpaque("utcNow"),
}

// ---------------------------------------------------------------------
// Function implementations — pure
// ---------------------------------------------------------------------

func fnParameters(ctx *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("parameters() takes 1 arg")
	}
	name, _ := args[0].(string)
	if v, ok := ctx.Parameters[name]; ok {
		// ARM parameter objects may wrap values under "defaultValue"
		// or "value"; unwrap the common case transparently.
		if m, ok := v.(map[string]interface{}); ok {
			if inner, ok := m["value"]; ok {
				return inner, nil
			}
			if inner, ok := m["defaultValue"]; ok {
				return inner, nil
			}
		}
		return v, nil
	}
	return opaqueValue("parameter:" + name), nil
}

func fnVariables(ctx *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("variables() takes 1 arg")
	}
	name, _ := args[0].(string)
	if v, ok := ctx.Variables[name]; ok {
		return v, nil
	}
	return opaqueValue("variable:" + name), nil
}

func fnCoalesce(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	for _, a := range args {
		if a != nil {
			if s, ok := a.(string); ok && s == "" {
				continue
			}
			return a, nil
		}
	}
	return nil, nil
}

func fnIf(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("if() takes 3 args")
	}
	cond := truthy(args[0])
	if cond {
		return args[1], nil
	}
	return args[2], nil
}

func fnEquals(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("equals() takes 2 args")
	}
	return equalValues(args[0], args[1]), nil
}

func fnAnd(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	for _, a := range args {
		if !truthy(a) {
			return false, nil
		}
	}
	return true, nil
}

func fnOr(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	for _, a := range args {
		if truthy(a) {
			return true, nil
		}
	}
	return false, nil
}

func fnNot(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("not() takes 1 arg")
	}
	return !truthy(args[0]), nil
}

func fnBool(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("bool() takes 1 arg")
	}
	return truthy(args[0]), nil
}

func fnEmpty(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("empty() takes 1 arg")
	}
	switch v := args[0].(type) {
	case nil:
		return true, nil
	case string:
		return v == "", nil
	case []interface{}:
		return len(v) == 0, nil
	case map[string]interface{}:
		return len(v) == 0, nil
	}
	return false, nil
}

// Arithmetic
func fnAdd(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("add() takes 2 args")
	}
	return numericOp(args[0], args[1], func(a, b float64) float64 { return a + b })
}
func fnSub(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("sub() takes 2 args")
	}
	return numericOp(args[0], args[1], func(a, b float64) float64 { return a - b })
}
func fnMul(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("mul() takes 2 args")
	}
	return numericOp(args[0], args[1], func(a, b float64) float64 { return a * b })
}
func fnDiv(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("div() takes 2 args")
	}
	return numericOp(args[0], args[1], func(a, b float64) float64 {
		if b == 0 {
			return 0
		}
		return a / b
	})
}
func fnMod(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("mod() takes 2 args")
	}
	a := toInt(args[0])
	b := toInt(args[1])
	if b == 0 {
		return 0, nil
	}
	return a % b, nil
}
func fnMin(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	best := float64(0)
	first := true
	for _, a := range args {
		if aa, ok := args[0].([]interface{}); ok && len(args) == 1 {
			return fnMin(nil, aa)
		}
		f := toFloat(a)
		if first || f < best {
			best = f
			first = false
		}
	}
	if first {
		return 0, nil
	}
	return best, nil
}
func fnMax(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	best := float64(0)
	first := true
	for _, a := range args {
		if aa, ok := args[0].([]interface{}); ok && len(args) == 1 {
			return fnMax(nil, aa)
		}
		f := toFloat(a)
		if first || f > best {
			best = f
			first = false
		}
	}
	if first {
		return 0, nil
	}
	return best, nil
}
func fnInt(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("int() takes 1 arg")
	}
	return toInt(args[0]), nil
}
func fnFloat(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("float() takes 1 arg")
	}
	return toFloat(args[0]), nil
}

// String
func fnConcat(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	// concat accepts either strings or arrays; arrays merge, strings
	// concatenate. If any arg is an array, treat all as arrays.
	arrayMode := false
	for _, a := range args {
		if _, ok := a.([]interface{}); ok {
			arrayMode = true
			break
		}
	}
	if arrayMode {
		out := []interface{}{}
		for _, a := range args {
			if arr, ok := a.([]interface{}); ok {
				out = append(out, arr...)
			} else {
				out = append(out, a)
			}
		}
		return out, nil
	}
	var b strings.Builder
	for _, a := range args {
		b.WriteString(toString(a))
	}
	return b.String(), nil
}

func fnFormat(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) == 0 {
		return "", nil
	}
	fmtStr := toString(args[0])
	rest := args[1:]
	// ARM format uses {0}, {1}, ... placeholders.
	result := fmtStr
	for i, r := range rest {
		result = strings.ReplaceAll(result, "{"+strconv.Itoa(i)+"}", toString(r))
	}
	return result, nil
}

func fnLength(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("length() takes 1 arg")
	}
	switch v := args[0].(type) {
	case string:
		return len(v), nil
	case []interface{}:
		return len(v), nil
	case map[string]interface{}:
		return len(v), nil
	}
	return 0, nil
}

func fnSubstring(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("substring() takes 2 or 3 args")
	}
	s := toString(args[0])
	start := toInt(args[1])
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		start = len(s)
	}
	if len(args) == 2 {
		return s[start:], nil
	}
	length := toInt(args[2])
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	if end < start {
		end = start
	}
	return s[start:end], nil
}

func fnToLower(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return strings.ToLower(toString(args[0])), nil
}
func fnToUpper(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return strings.ToUpper(toString(args[0])), nil
}
func fnTrim(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return strings.TrimSpace(toString(args[0])), nil
}
func fnPadLeft(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("padLeft() takes 2 or 3 args")
	}
	s := toString(args[0])
	width := toInt(args[1])
	pad := " "
	if len(args) >= 3 {
		pad = toString(args[2])
		if pad == "" {
			pad = " "
		}
	}
	for len(s) < width {
		s = pad + s
	}
	return s[len(s)-width:], nil
}
func fnReplace(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("replace() takes 3 args")
	}
	return strings.ReplaceAll(toString(args[0]), toString(args[1]), toString(args[2])), nil
}
func fnSplit(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("split() takes 2 args")
	}
	parts := strings.Split(toString(args[0]), toString(args[1]))
	out := make([]interface{}, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out, nil
}
func fnStartsWith(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("startsWith() takes 2 args")
	}
	return strings.HasPrefix(toString(args[0]), toString(args[1])), nil
}
func fnEndsWith(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("endsWith() takes 2 args")
	}
	return strings.HasSuffix(toString(args[0]), toString(args[1])), nil
}
func fnContains(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("contains() takes 2 args")
	}
	switch haystack := args[0].(type) {
	case string:
		return strings.Contains(haystack, toString(args[1])), nil
	case []interface{}:
		for _, h := range haystack {
			if equalValues(h, args[1]) {
				return true, nil
			}
		}
		return false, nil
	case map[string]interface{}:
		_, ok := haystack[toString(args[1])]
		return ok, nil
	}
	return false, nil
}
func fnIndexOf(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("indexOf() takes 2 args")
	}
	return strings.Index(toString(args[0]), toString(args[1])), nil
}
func fnString(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("string() takes 1 arg")
	}
	return toString(args[0]), nil
}
func fnURI(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("uri() takes 2 args")
	}
	base := toString(args[0])
	rel := toString(args[1])
	if strings.HasSuffix(base, "/") {
		base = strings.TrimRight(base, "/")
	}
	return base + "/" + strings.TrimLeft(rel, "/"), nil
}
func fnURIComponent(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	// Not implementing full URL encoding — return string as-is which
	// is acceptable for rule matching on expression-evaluated URIs.
	return toString(args[0]), nil
}
func fnURIComponentToString(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return toString(args[0]), nil
}
func fnBase64(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return base64.StdEncoding.EncodeToString([]byte(toString(args[0]))), nil
}
func fnBase64ToString(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	data, err := base64.StdEncoding.DecodeString(toString(args[0]))
	if err != nil {
		return "", nil
	}
	return string(data), nil
}
func fnBase64ToJSON(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	data, err := base64.StdEncoding.DecodeString(toString(args[0]))
	if err != nil {
		return nil, nil
	}
	var out interface{}
	_ = json.Unmarshal(data, &out)
	return out, nil
}
func fnDataURI(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return "data:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(toString(args[0]))), nil
}
func fnDataURIToString(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	s := toString(args[0])
	if idx := strings.Index(s, ","); idx >= 0 {
		data, err := base64.StdEncoding.DecodeString(s[idx+1:])
		if err == nil {
			return string(data), nil
		}
	}
	return s, nil
}

// Array / object
func fnArray(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("array() takes 1 arg")
	}
	if arr, ok := args[0].([]interface{}); ok {
		return arr, nil
	}
	return []interface{}{args[0]}, nil
}
func fnCreateArray(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	return append([]interface{}{}, args...), nil
}
func fnFirst(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("first() takes 1 arg")
	}
	if a, ok := args[0].([]interface{}); ok && len(a) > 0 {
		return a[0], nil
	}
	if s, ok := args[0].(string); ok && len(s) > 0 {
		return string(s[0]), nil
	}
	return nil, nil
}
func fnLast(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if a, ok := args[0].([]interface{}); ok && len(a) > 0 {
		return a[len(a)-1], nil
	}
	if s, ok := args[0].(string); ok && len(s) > 0 {
		return string(s[len(s)-1]), nil
	}
	return nil, nil
}
func fnSkip(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("skip() takes 2 args")
	}
	n := toInt(args[1])
	if a, ok := args[0].([]interface{}); ok {
		if n > len(a) {
			n = len(a)
		}
		return a[n:], nil
	}
	return args[0], nil
}
func fnTake(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("take() takes 2 args")
	}
	n := toInt(args[1])
	if a, ok := args[0].([]interface{}); ok {
		if n > len(a) {
			n = len(a)
		}
		return a[:n], nil
	}
	if s, ok := args[0].(string); ok {
		if n > len(s) {
			n = len(s)
		}
		return s[:n], nil
	}
	return args[0], nil
}
func fnUnion(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	// For arrays: concat unique. For objects: merge.
	if len(args) == 0 {
		return nil, nil
	}
	if _, ok := args[0].(map[string]interface{}); ok {
		out := map[string]interface{}{}
		for _, a := range args {
			if m, ok := a.(map[string]interface{}); ok {
				for k, v := range m {
					out[k] = v
				}
			}
		}
		return out, nil
	}
	seen := map[string]bool{}
	out := []interface{}{}
	for _, a := range args {
		if arr, ok := a.([]interface{}); ok {
			for _, v := range arr {
				k := toString(v)
				if !seen[k] {
					seen[k] = true
					out = append(out, v)
				}
			}
		}
	}
	return out, nil
}
func fnIntersection(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) == 0 {
		return nil, nil
	}
	first, ok := args[0].([]interface{})
	if !ok {
		return nil, nil
	}
	out := []interface{}{}
	for _, candidate := range first {
		inAll := true
		for _, other := range args[1:] {
			arr, ok := other.([]interface{})
			if !ok {
				inAll = false
				break
			}
			found := false
			for _, v := range arr {
				if equalValues(candidate, v) {
					found = true
					break
				}
			}
			if !found {
				inAll = false
				break
			}
		}
		if inAll {
			out = append(out, candidate)
		}
	}
	return out, nil
}
func fnRange(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("range() takes 2 args")
	}
	start := toInt(args[0])
	n := toInt(args[1])
	out := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, start+i)
	}
	return out, nil
}
func fnCreateObject(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	out := map[string]interface{}{}
	for i := 0; i+1 < len(args); i += 2 {
		out[toString(args[i])] = args[i+1]
	}
	return out, nil
}
func fnJSON(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("json() takes 1 arg")
	}
	var out interface{}
	if err := json.Unmarshal([]byte(toString(args[0])), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func fnResourceID(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	// resourceId optionally takes subscription/rg prefix args; real
	// logic: last arg is the resource name, second-to-last is type.
	// ARGUS only needs a string ID that looks ARM-shaped so child-type
	// derivation works.
	if len(args) == 0 {
		return "", nil
	}
	// Find the resource type (contains "/") and name(s).
	var types []string
	var names []string
	for _, a := range args {
		s := toString(a)
		if strings.Contains(s, "/") && len(types) == 0 {
			types = append(types, s)
		} else if len(types) > 0 {
			names = append(names, s)
		}
	}
	if len(types) == 0 {
		return "", nil
	}
	id := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/argus-rg/providers/" + types[0]
	for _, n := range names {
		id += "/" + n
	}
	return id, nil
}

func fnGUID(_ *ARMExprContext, args []interface{}) (interface{}, error) {
	// Deterministic based on args — ARM's own spec.
	h := uint64(14695981039346656037) // FNV offset
	for _, a := range args {
		for _, b := range []byte(toString(a)) {
			h = (h ^ uint64(b)) * 1099511628211
		}
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", uint32(h>>32), uint16(h>>16), uint16(h), uint16(h>>48), h), nil
}

func fnUniqueString(ctx *ARMExprContext, args []interface{}) (interface{}, error) {
	g, err := fnGUID(ctx, args)
	if err != nil {
		return nil, err
	}
	return strings.ReplaceAll(g.(string), "-", "")[:13], nil
}

// fnOpaque returns a function that evaluates to an opaque marker.
// Used for runtime-state ARM functions that ARGUS cannot evaluate.
func fnOpaque(name string) armFn {
	return func(_ *ARMExprContext, args []interface{}) (interface{}, error) {
		argParts := make([]string, len(args))
		for i, a := range args {
			argParts[i] = toString(a)
		}
		return opaqueValue(name + "(" + strings.Join(argParts, ",") + ")"), nil
	}
}

// opaqueValue wraps a runtime-only marker in a string that carries a
// distinctive prefix so downstream code can detect it and handle
// accordingly.
func opaqueValue(tag string) string {
	return opaqueMarker + tag + ">>"
}

// ---------------------------------------------------------------------
// Type coercion helpers
// ---------------------------------------------------------------------

func toString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return string(x)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func toInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		i, err := strconv.Atoi(x)
		if err == nil {
			return i
		}
	case json.Number:
		i, err := x.Int64()
		if err == nil {
			return int(i)
		}
	}
	return 0
}

func toFloat(v interface{}) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case float64:
		return x
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err == nil {
			return f
		}
	}
	return 0
}

func truthy(v interface{}) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != "" && !strings.HasPrefix(x, opaqueMarker)
	case int:
		return x != 0
	case float64:
		return x != 0
	case []interface{}:
		return len(x) > 0
	case map[string]interface{}:
		return len(x) > 0
	}
	return true
}

func equalValues(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == b
	}
	return toString(a) == toString(b)
}

func numericOp(a, b interface{}, op func(float64, float64) float64) (interface{}, error) {
	f := op(toFloat(a), toFloat(b))
	if f == float64(int64(f)) {
		return int(f), nil
	}
	return f, nil
}
