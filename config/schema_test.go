package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSchemaIncludesRequestFieldMatchers(t *testing.T) {
	schema := readConfigSchema(t)
	match := schema["definitions"].(map[string]any)["match"].(map[string]any)
	properties := match["properties"].(map[string]any)
	matchType := properties["type"].(map[string]any)
	typeEnum := matchType["enum"].([]any)

	for _, want := range []string{"method", "query-param", "cookie", "proxy-ip", "proxy-asn", "proxy-iplist"} {
		if !schemaStringListContains(typeEnum, want) {
			t.Fatalf("expected match type enum to include %q", want)
		}
	}

	if !schemaRequiresKeyForTypes(match, "header", "query-param", "cookie") {
		t.Fatal("expected schema to require key for header, query-param, and cookie match types")
	}
}

func readConfigSchema(t *testing.T) map[string]any {
	t.Helper()

	data, err := os.ReadFile("../config.schema.json")
	if err != nil {
		t.Fatalf("read config schema: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse config schema: %v", err)
	}
	return schema
}

func schemaRequiresKeyForTypes(match map[string]any, types ...string) bool {
	allOf := match["allOf"].([]any)
	for _, condition := range allOf {
		conditionMap := condition.(map[string]any)
		ifBlock := conditionMap["if"].(map[string]any)
		properties := ifBlock["properties"].(map[string]any)
		typeBlock := properties["type"].(map[string]any)
		typeEnum, ok := typeBlock["enum"].([]any)
		if !ok {
			continue
		}

		hasAllTypes := true
		for _, matchType := range types {
			if !schemaStringListContains(typeEnum, matchType) {
				hasAllTypes = false
				break
			}
		}
		if !hasAllTypes {
			continue
		}

		thenBlock := conditionMap["then"].(map[string]any)
		required := thenBlock["required"].([]any)
		return schemaStringListContains(required, "key")
	}
	return false
}

func schemaStringListContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
