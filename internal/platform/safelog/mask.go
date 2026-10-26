// Package safelog provides structured logging with recursive PAN/CVV redaction.
package safelog

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var panInText = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

var sensitiveKeys = map[string]struct{}{
	"cardnumber":                  {},
	"encryptedcardnumber":         {},
	"primaryaccountnumber":        {},
	"pan":                         {},
	"cvv":                         {},
	"cvc":                         {},
	"cvv2":                        {},
	"cvc2":                        {},
	"securitycode":                {},
	"cardsecuritycode":            {},
	"sensitiveauthenticationdata": {},
	"trackdata":                   {},
	"track1":                      {},
	"track2":                      {},
}

// MaskPAN returns a display-safe representation of a card number.
// Only the last four digits are retained.
func MaskPAN(value string) string {
	digits := digitsOnly(value)
	if len(digits) < 4 {
		return "[REDACTED]"
	}
	return "**** **** **** " + digits[len(digits)-4:]
}

// MaskString redacts card-like sequences (13-19 digits with optional spaces or
// dashes) found anywhere in a free-form string.
func MaskString(value string) string {
	return panInText.ReplaceAllStringFunc(value, MaskPAN)
}

// Redact deep-copies a value and masks sensitive fields and card numbers.
// It is safe to pass maps, structs, pointers, slices and nested structures.
func Redact(value any) any {
	return sanitize(reflect.ValueOf(value), 0)
}

// RedactMap sanitizes a structured log field map.
func RedactMap(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		if isSensitiveKey(key) {
			out[key] = maskSensitiveValue(key, value)
			continue
		}
		out[key] = sanitize(reflect.ValueOf(value), 0)
	}
	return out
}

func sanitize(value reflect.Value, depth int) any {
	if !value.IsValid() {
		return nil
	}
	if depth > 12 {
		return "[MAX_DEPTH]"
	}
	if (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) && value.IsNil() {
		return nil
	}
	if value.CanInterface() {
		switch typed := value.Interface().(type) {
		case time.Time:
			return typed
		case error:
			return MaskString(typed.Error())
		case fmt.Stringer:
			return MaskString(typed.String())
		}
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		return sanitize(value.Elem(), depth+1)
	}

	switch value.Kind() {
	case reflect.String:
		return MaskString(value.String())
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		return value.Float()
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			return "[BINARY]"
		}
		out := make([]any, 0, value.Len())
		for i := 0; i < value.Len(); i++ {
			out = append(out, sanitize(value.Index(i), depth+1))
		}
		return out
	case reflect.Map:
		out := make(map[string]any, value.Len())
		iter := value.MapRange()
		for iter.Next() {
			key := fmt.Sprint(iter.Key().Interface())
			if isSensitiveKey(key) {
				out[key] = maskSensitiveValue(key, iter.Value().Interface())
				continue
			}
			out[key] = sanitize(iter.Value(), depth+1)
		}
		return out
	case reflect.Struct:
		out := make(map[string]any)
		valueType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := valueType.Field(i)
			if field.PkgPath != "" {
				continue
			}
			key := field.Name
			if tag := field.Tag.Get("json"); tag != "" {
				parts := strings.Split(tag, ",")
				if parts[0] == "-" {
					continue
				}
				if parts[0] != "" {
					key = parts[0]
				}
			}
			if isSensitiveKey(key) {
				out[key] = maskSensitiveValue(key, value.Field(i).Interface())
				continue
			}
			out[key] = sanitize(value.Field(i), depth+1)
		}
		return out
	default:
		if value.CanInterface() {
			return MaskString(fmt.Sprint(value.Interface()))
		}
		return "[UNSUPPORTED]"
	}
}

func maskSensitiveValue(key string, value any) any {
	if value == nil {
		return nil
	}
	normalized := normalizeKey(key)
	if isAuthenticationDataKey(normalized) {
		return "***"
	}
	raw := fmt.Sprint(value)
	if digitsOnly(raw) == "" {
		return "[REDACTED]"
	}
	return MaskPAN(raw)
}

func isSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	if _, ok := sensitiveKeys[normalized]; ok {
		return true
	}
	// Catch variants such as billing_card_number or encrypted_card_number.
	return strings.HasSuffix(normalized, "cardnumber")
}

func isAuthenticationDataKey(normalized string) bool {
	switch normalized {
	case "cvv", "cvc", "cvv2", "cvc2", "securitycode", "cardsecuritycode", "sensitiveauthenticationdata":
		return true
	default:
		return false
	}
}

func normalizeKey(key string) string {
	var builder strings.Builder
	builder.Grow(len(key))
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func digitsOnly(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		if r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
