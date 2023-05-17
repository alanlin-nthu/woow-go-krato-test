// Code generated by github.com/atombender/go-jsonschema, DO NOT EDIT.

package service

import "fmt"
import "encoding/json"

type PersonSchemaJsonTraits struct {
	// Email corresponds to the JSON schema field "email".
	Email string `json:"email" yaml:"email"`

	// Name corresponds to the JSON schema field "name".
	Name *PersonSchemaJsonTraitsName `json:"name,omitempty" yaml:"name,omitempty"`

	// connect information corresponds to the JSON schema field "info".
	Info *PersonSchemaJsonTraitsInfo `json:"info,omitempty" yaml:"info,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *PersonSchemaJsonTraits) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["email"]; !ok || v == nil {
		return fmt.Errorf("field email in PersonSchemaJsonTraits: required")
	}
	type Plain PersonSchemaJsonTraits
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = PersonSchemaJsonTraits(plain)
	return nil
}

type PersonSchemaJsonTraitsName struct {
	// First corresponds to the JSON schema field "first".
	First *string `json:"first,omitempty" yaml:"first,omitempty"`

	// Last corresponds to the JSON schema field "last".
	Last *string `json:"last,omitempty" yaml:"last,omitempty"`
}

type PersonSchemaJsonTraitsInfo struct {
	// Mobile corresponds to the JSON schema field "mobile".
	Mobile *string `json:"mobile,omitempty" yaml:"mobile,omitempty"`

	// Domain corresponds to the JSON schema field "domain".
	Domain *string `json:"domain,omitempty" yaml:"domain,omitempty"`

	// Key corresponds to the JSON schema field "key".
	Key *string `json:"key,omitempty" yaml:"key,omitempty"`
}

type PersonSchemaJson struct {
	// Traits corresponds to the JSON schema field "traits".
	Traits *PersonSchemaJsonTraits `json:"traits,omitempty" yaml:"traits,omitempty"`
}
