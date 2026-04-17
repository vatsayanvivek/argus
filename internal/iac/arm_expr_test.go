package iac

import (
	"strings"
	"testing"
)

// eval is a tiny wrapper so tests read cleanly: eval(t, "add(1,2)") → 3.
func eval(t *testing.T, src string, ctx *ARMExprContext) interface{} {
	t.Helper()
	got, err := EvaluateExpression(src, ctx)
	if err != nil {
		t.Fatalf("eval %q: %v", src, err)
	}
	return got
}

// Small context used by most tests.
func testCtx() *ARMExprContext {
	return &ARMExprContext{
		Parameters: map[string]interface{}{
			"env":      "prod",
			"location": "eastus",
			"count":    3,
			"enabled":  true,
			"tags":     map[string]interface{}{"team": "security"},
			"defaulted": map[string]interface{}{
				"defaultValue": "fallback",
			},
		},
		Variables: map[string]interface{}{
			"prefix": "kv-prod",
			"sizes":  []interface{}{float64(1), float64(2), float64(3)},
		},
	}
}

// ---------------------------------------------------------------------
// Literal + primitive evaluation
// ---------------------------------------------------------------------

func TestEval_StringLiteral(t *testing.T) {
	if got := eval(t, "'hello'", nil); got != "hello" {
		t.Errorf("got %v", got)
	}
}

func TestEval_StringLiteralWithEscapedQuote(t *testing.T) {
	if got := eval(t, "'it''s fine'", nil); got != "it's fine" {
		t.Errorf("got %v", got)
	}
}

func TestEval_IntLiteral(t *testing.T) {
	if got := eval(t, "42", nil); got != 42 {
		t.Errorf("got %v (%T)", got, got)
	}
}

func TestEval_NegativeInt(t *testing.T) {
	if got := eval(t, "-5", nil); got != -5 {
		t.Errorf("got %v", got)
	}
}

func TestEval_BoolLiterals(t *testing.T) {
	if got := eval(t, "true", nil); got != true {
		t.Errorf("got %v", got)
	}
	if got := eval(t, "false", nil); got != false {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------
// Deployment / context
// ---------------------------------------------------------------------

func TestEval_Parameters(t *testing.T) {
	if got := eval(t, "parameters('env')", testCtx()); got != "prod" {
		t.Errorf("got %v", got)
	}
}

func TestEval_Parameters_UnwrapsDefaultValue(t *testing.T) {
	// If parameter value is wrapped in {"defaultValue": ...}, unwrap.
	if got := eval(t, "parameters('defaulted')", testCtx()); got != "fallback" {
		t.Errorf("defaultValue unwrap: got %v", got)
	}
}

func TestEval_Parameters_MissingReturnsOpaque(t *testing.T) {
	got := eval(t, "parameters('missing')", testCtx())
	s, _ := got.(string)
	if !strings.HasPrefix(s, opaqueMarker) {
		t.Errorf("missing param should return opaque marker, got %v", got)
	}
}

func TestEval_Variables(t *testing.T) {
	if got := eval(t, "variables('prefix')", testCtx()); got != "kv-prod" {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------
// String functions
// ---------------------------------------------------------------------

func TestEval_Concat(t *testing.T) {
	if got := eval(t, "concat('a', 'b', 'c')", nil); got != "abc" {
		t.Errorf("got %v", got)
	}
}

func TestEval_Concat_UsesParameters(t *testing.T) {
	if got := eval(t, "concat('kv-', parameters('env'))", testCtx()); got != "kv-prod" {
		t.Errorf("got %v", got)
	}
}

func TestEval_Format(t *testing.T) {
	if got := eval(t, "format('{0}-{1}', 'kv', parameters('env'))", testCtx()); got != "kv-prod" {
		t.Errorf("got %v", got)
	}
}

func TestEval_SubstringAndToLower(t *testing.T) {
	if got := eval(t, "toLower(substring('HELLO', 0, 3))", nil); got != "hel" {
		t.Errorf("got %v", got)
	}
}

func TestEval_Replace(t *testing.T) {
	if got := eval(t, "replace('foo-bar', '-', '_')", nil); got != "foo_bar" {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------

func TestEval_Add(t *testing.T) {
	if got := eval(t, "add(2, 3)", nil); got != 5 {
		t.Errorf("got %v (%T)", got, got)
	}
}

func TestEval_ChainedArithmetic(t *testing.T) {
	// ARM has no infix ops; expressions are deeply nested function calls.
	// mul(add(2,3), 4) = (2+3)*4 = 20
	if got := eval(t, "mul(add(2, 3), 4)", nil); got != 20 {
		t.Errorf("got %v", got)
	}
}

func TestEval_Div_AvoidsDivByZero(t *testing.T) {
	if got := eval(t, "div(10, 0)", nil); got != 0 {
		t.Errorf("expected safe 0 on div-by-zero, got %v", got)
	}
}

// ---------------------------------------------------------------------
// Logical / conditional
// ---------------------------------------------------------------------

func TestEval_If_True(t *testing.T) {
	if got := eval(t, "if(equals(parameters('env'), 'prod'), 'yes', 'no')", testCtx()); got != "yes" {
		t.Errorf("got %v", got)
	}
}

func TestEval_If_False(t *testing.T) {
	if got := eval(t, "if(equals(parameters('env'), 'dev'), 'yes', 'no')", testCtx()); got != "no" {
		t.Errorf("got %v", got)
	}
}

func TestEval_And_Or_Not(t *testing.T) {
	if got := eval(t, "and(true, equals(1, 1))", nil); got != true {
		t.Errorf("and: %v", got)
	}
	if got := eval(t, "or(false, equals(1, 2))", nil); got != false {
		t.Errorf("or: %v", got)
	}
	if got := eval(t, "not(false)", nil); got != true {
		t.Errorf("not: %v", got)
	}
}

// ---------------------------------------------------------------------
// Arrays + property access
// ---------------------------------------------------------------------

func TestEval_First(t *testing.T) {
	if got := eval(t, "first(variables('sizes'))", testCtx()); got != float64(1) {
		t.Errorf("got %v (%T)", got, got)
	}
}

func TestEval_Length_String(t *testing.T) {
	if got := eval(t, "length('hello')", nil); got != 5 {
		t.Errorf("got %v", got)
	}
}

func TestEval_Length_Array(t *testing.T) {
	if got := eval(t, "length(variables('sizes'))", testCtx()); got != 3 {
		t.Errorf("got %v", got)
	}
}

func TestEval_PropertyAccess(t *testing.T) {
	// parameters('tags').team
	if got := eval(t, "parameters('tags').team", testCtx()); got != "security" {
		t.Errorf("got %v", got)
	}
}

func TestEval_BracketIndex(t *testing.T) {
	if got := eval(t, "variables('sizes')[1]", testCtx()); got != float64(2) {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------
// resourceId
// ---------------------------------------------------------------------

func TestEval_ResourceID(t *testing.T) {
	got, _ := EvaluateExpression("resourceId('Microsoft.KeyVault/vaults', 'kv-prod')", nil)
	s, _ := got.(string)
	if !strings.Contains(s, "Microsoft.KeyVault/vaults/kv-prod") {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------
// Runtime functions → opaque markers
// ---------------------------------------------------------------------

func TestEval_Reference_IsOpaque(t *testing.T) {
	got := eval(t, "reference(resourceId('Microsoft.Storage/storageAccounts', 'stprod'))", nil)
	s, _ := got.(string)
	if !strings.HasPrefix(s, opaqueMarker) {
		t.Errorf("reference() should be opaque, got %v", got)
	}
	if !strings.Contains(s, "reference(") {
		t.Errorf("opaque marker should name the function, got %v", got)
	}
}

func TestEval_ListKeys_IsOpaque(t *testing.T) {
	got := eval(t, "listKeys('id', '2023-01-01')", nil)
	s, _ := got.(string)
	if !strings.HasPrefix(s, opaqueMarker) {
		t.Errorf("listKeys() should be opaque, got %v", got)
	}
}

func TestEval_Environment_IsOpaque(t *testing.T) {
	got := eval(t, "environment()", nil)
	s, _ := got.(string)
	if !strings.HasPrefix(s, opaqueMarker) {
		t.Errorf("environment() should be opaque")
	}
}

// ---------------------------------------------------------------------
// ResolveARMValue end-to-end on a template fragment
// ---------------------------------------------------------------------

func TestResolveARMValue_NestedStructure(t *testing.T) {
	// Imagine this is a "properties" block from an ARM template.
	fragment := map[string]interface{}{
		"name":            "[concat('kv-', parameters('env'))]",
		"accessTier":      "Hot",
		"enabledForAuth":  "[equals(parameters('env'), 'prod')]",
		"networkAcls": map[string]interface{}{
			"defaultAction": "[if(equals(parameters('env'), 'prod'), 'Deny', 'Allow')]",
		},
		"zones": []interface{}{
			"[concat(parameters('location'), '-1')]",
			"[concat(parameters('location'), '-2')]",
		},
	}
	ctx := testCtx()
	resolved := ResolveARMValue(fragment, ctx).(map[string]interface{})
	if resolved["name"] != "kv-prod" {
		t.Errorf("name: %v", resolved["name"])
	}
	if resolved["enabledForAuth"] != true {
		t.Errorf("enabledForAuth: %v (%T)", resolved["enabledForAuth"], resolved["enabledForAuth"])
	}
	if na := resolved["networkAcls"].(map[string]interface{}); na["defaultAction"] != "Deny" {
		t.Errorf("networkAcls.defaultAction: %v", na["defaultAction"])
	}
	zones := resolved["zones"].([]interface{})
	if zones[0] != "eastus-1" || zones[1] != "eastus-2" {
		t.Errorf("zones: %v", zones)
	}
}

// ---------------------------------------------------------------------
// Integration with ARM parser — template with expressions
// ---------------------------------------------------------------------

func TestParseARMTemplate_ResolvesExpressionsAgainstParameters(t *testing.T) {
	body := `{
      "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "parameters": {
        "env": {"defaultValue": "prod"},
        "location": {"value": "eastus"}
      },
      "variables": {
        "kvName": "[concat('kv-', parameters('env'))]"
      },
      "resources": [{
        "type": "Microsoft.KeyVault/vaults",
        "apiVersion": "2023-01-01",
        "name": "[variables('kvName')]",
        "location": "[parameters('location')]",
        "properties": {
          "enablePurgeProtection": "[equals(parameters('env'), 'prod')]",
          "networkAcls": {
            "defaultAction": "[if(equals(parameters('env'), 'prod'), 'Deny', 'Allow')]"
          }
        }
      }]
    }`
	tpl, err := ParseARMTemplate([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := tpl.Resources[0]
	if r.Name != "kv-prod" {
		t.Errorf("name: %q (expression not resolved)", r.Name)
	}
	if r.Location != "eastus" {
		t.Errorf("location: %q", r.Location)
	}
	if r.Properties["enablePurgeProtection"] != true {
		t.Errorf("enablePurgeProtection: %v", r.Properties["enablePurgeProtection"])
	}
	if na := r.Properties["networkAcls"].(map[string]interface{}); na["defaultAction"] != "Deny" {
		t.Errorf("networkAcls.defaultAction: %v", na["defaultAction"])
	}
}

// TestParseARMTemplate_OpaqueForRuntimeFunctions proves that a runtime
// function like reference() leaves an opaque marker in the resolved
// value — the correct behaviour.
func TestParseARMTemplate_OpaqueForRuntimeFunctions(t *testing.T) {
	body := `{
      "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "resources": [{
        "type": "Microsoft.Storage/storageAccounts",
        "apiVersion": "2023-01-01",
        "name": "stprod",
        "location": "eastus",
        "properties": {
          "fromReference": "[reference(resourceId('Microsoft.Storage/storageAccounts', 'dep')).primaryEndpoints.blob]"
        }
      }]
    }`
	tpl, err := ParseARMTemplate([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, _ := tpl.Resources[0].Properties["fromReference"].(string)
	if !strings.HasPrefix(got, opaqueMarker) {
		t.Errorf("reference() result should be opaque marker, got %q", got)
	}
}

// TestIsARMExpression_EdgeCases verifies the escape convention.
func TestIsARMExpression_EdgeCases(t *testing.T) {
	cases := map[string]bool{
		"[foo]":     true,
		"[[foo]]":   false, // escaped literal, not an expression
		"foo":       false,
		"[":         false,
		"]":         false,
		"":          false,
		"[a][b]":    true,  // technically an expression per ARM
	}
	for in, want := range cases {
		if got := IsARMExpression(in); got != want {
			t.Errorf("IsARMExpression(%q) = %v, want %v", in, got, want)
		}
	}
}
