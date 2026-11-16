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

func TestFileAndInputValidators(t *testing.T) {
	if err := ValidateFilePath(""); err == nil {
		t.Error("empty path accepted")
	}
	if err := ValidateFilePath("definitely-not-here"); err == nil {
		t.Error("missing path accepted")
	}
	if err := ValidateFilePath(t.TempDir()); err == nil {
		t.Error("directory accepted as file")
	}
	if err := ValidateResultMax(0); err != nil {
		t.Errorf("result_max=0 should mean the API default: %v", err)
	}
	if err := ValidateResultMax(-1); err == nil {
		t.Error("negative result_max accepted")
	}
	if err := ValidateResultMax(1001); err == nil {
		t.Error("oversized result_max accepted")
	}
	if err := ValidateImphash("not-a-hash"); err == nil {
		t.Error("bad imphash accepted")
	}
	if err := ValidateHash("bad"); err == nil {
		t.Error("bad hash accepted")
	}
}
