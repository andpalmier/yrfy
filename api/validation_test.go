package api

import "testing"

func TestValidateMD5(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"valid", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"empty", "", true},
		{"too short", "abc", true},
		{"not hex", "z41d8cd98f00b204e9800998ecf8427e", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateMD5(tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("ValidateMD5() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSHA256(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"valid", "88d862aeb067278155c67a6d4e5be927b36f08149c950d75a3a419eb20560aa1", false},
		{"empty", "", true},
		{"too short", "abc", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSHA256(tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("ValidateSHA256() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateYARARule(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{"valid", "Win_Emotet", false},
		{"empty", "", true},
		{"too long", "ThisRuleNameIsWayTooLongAndShouldDefinitelyFailBecauseItExceedsTheLimitOfOneHundredCharactersWhichIsQuiteALotForARuleNameIThinkButWeMustBeSure", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateYARARuleName(tt.rule); (err != nil) != tt.wantErr {
				t.Errorf("ValidateYARARuleName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
