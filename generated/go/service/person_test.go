package service_test

import (
	"encoding/json"
	"testing"

	"github.com/atreya2011/kratos-test/generated/go/service"
)

func TestPersonSchemaJsonTraits_UnmarshalJSON(t *testing.T) {
	jsonData := []byte(`{"email": "test@example.com", "name": {"first": "John", "last": "Doe"}, "info": {"mobile": "1234567890", "domain": "123 Main St"}}`)

	var person service.PersonSchemaJsonTraits

	err := json.Unmarshal(jsonData, &person)
	if err != nil {
		t.Errorf("UnmarshalJSON returned an error: %v", err)
	}

	// Perform assertions on the person object to verify the expected values.
	if person.Email != "test@example.com" {
		t.Errorf("Email field not parsed correctly. Expected: test@example.com, Got: %s", person.Email)
	}
	if person.Name == nil || person.Name.First == nil || *person.Name.First != "John" {
		t.Error("Name.First field not parsed correctly.")
	}
	if person.Name == nil || person.Name.Last == nil || *person.Name.Last != "Doe" {
		t.Error("Name.Last field not parsed correctly.")
	}
	if person.Info == nil || person.Info.Mobile == nil || *person.Info.Mobile != "1234567890" {
		t.Error("Info.Phone field not parsed correctly.")
	}
	if person.Info == nil || person.Info.Domain == nil || *person.Info.Domain != "123 Main St" {
		t.Error("Info.Address field not parsed correctly.")
	}

	t.Logf("service.PersonSchemaJsonTraits json: %v", person)
}
