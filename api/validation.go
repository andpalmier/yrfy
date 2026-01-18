package api

import (
	"fmt"
	"os"
	"regexp"
)

// sha256Regex matches valid SHA256 hashes (64 hexadecimal characters)
var sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// md5Regex matches valid MD5 hashes (32 hexadecimal characters)
var md5Regex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// sha1Regex matches valid SHA1 hashes (40 hexadecimal characters)
var sha1Regex = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// sha3Regex matches valid SHA3-384 hashes (96 hexadecimal characters)
var sha3Regex = regexp.MustCompile(`^[a-fA-F0-9]{96}$`)

// taskIDRegex matches valid task IDs (UUID format)
var taskIDRegex = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// yaraRuleRegex matches valid YARA rule names
var yaraRuleRegex = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// ValidateSHA256 checks if the input is a valid SHA256 hash
func ValidateSHA256(hash string) error {
	if !sha256Regex.MatchString(hash) {
		return fmt.Errorf("invalid SHA256 hash: must be 64 hexadecimal characters")
	}
	return nil
}

// ValidateMD5 checks if the input is a valid MD5 hash
func ValidateMD5(hash string) error {
	if !md5Regex.MatchString(hash) {
		return fmt.Errorf("invalid MD5 hash: must be 32 hexadecimal characters")
	}
	return nil
}

// ValidateHash checks if the input is a valid file hash (MD5, SHA1, SHA256, or SHA3-384)
func ValidateHash(hash string) error {
	if sha256Regex.MatchString(hash) || md5Regex.MatchString(hash) ||
		sha1Regex.MatchString(hash) || sha3Regex.MatchString(hash) {
		return nil
	}
	return fmt.Errorf("invalid hash: must be MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex), or SHA3-384 (96 hex)")
}

// ValidateTaskID checks if the input is a valid task ID
func ValidateTaskID(taskID string) error {
	if !taskIDRegex.MatchString(taskID) {
		return fmt.Errorf("invalid task ID: must be a valid UUID")
	}
	return nil
}

// ValidateYARARuleName checks if the input is a valid YARA rule name
func ValidateYARARuleName(name string) error {
	if name == "" {
		return fmt.Errorf("YARA rule name cannot be empty")
	}
	if len(name) > 100 {
		return fmt.Errorf("YARA rule name too long: maximum 100 characters")
	}
	if !yaraRuleRegex.MatchString(name) {
		return fmt.Errorf("invalid YARA rule name: only alphanumeric characters and underscores allowed")
	}
	return nil
}

// ValidateClamAVSignature checks if the input is a valid ClamAV signature name
func ValidateClamAVSignature(sig string) error {
	if sig == "" {
		return fmt.Errorf("ClamAV signature cannot be empty")
	}
	if len(sig) > 200 {
		return fmt.Errorf("ClamAV signature too long: maximum 200 characters")
	}
	return nil
}

// ValidateFilePath checks if a file exists and is readable
func ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("error accessing file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}
	return nil
}

// ValidateResultMax checks the result_max parameter
func ValidateResultMax(max int) error {
	if max < 1 {
		return fmt.Errorf("result_max must be at least 1")
	}
	if max > 1000 {
		return fmt.Errorf("result_max cannot exceed 1000")
	}
	return nil
}

// ValidateImphash checks an imphash
func ValidateImphash(hash string) error {
	if !md5Regex.MatchString(hash) {
		return fmt.Errorf("invalid imphash: must be 32 hexadecimal characters")
	}
	return nil
}

// ValidateTLSH checks a TLSH hash
func ValidateTLSH(hash string) error {
	if hash == "" {
		return fmt.Errorf("TLSH hash cannot be empty")
	}
	if len(hash) < 35 || len(hash) > 140 {
		return fmt.Errorf("invalid TLSH hash: unexpected length")
	}
	return nil
}

// ValidateIdentifier checks an identifier
func ValidateIdentifier(id string) error {
	if id == "" {
		return fmt.Errorf("identifier cannot be empty")
	}
	if len(id) > 64 {
		return fmt.Errorf("identifier too long: maximum 64 characters")
	}
	return nil
}
