package api

import "encoding/json"

// ScanOptions represents options for file scanning
type ScanOptions struct {
	ClamAVScan int    `json:"clamav_scan,omitempty"`
	Unpack     int    `json:"unpack,omitempty"`
	ShareFile  int    `json:"share_file,omitempty"`
	SkipKnown  int    `json:"skip_known,omitempty"`
	SkipNoisy  int    `json:"skip_noisy,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// ScanResponse represents the response from file scan submission
type ScanResponse struct {
	QueryStatus string `json:"query_status"`
	TaskID      string `json:"task_id,omitempty"`
	Data        struct {
		TaskID string `json:"task_id,omitempty"`
	} `json:"data,omitempty"`
}

// TaskResultResponse represents the response from get_results query
type TaskResultResponse struct {
	QueryStatus string      `json:"query_status"`
	Data        *TaskResult `json:"data,omitempty"`
}

// TaskResult contains the scan results for a task
type TaskResult struct {
	YARAifyParams *ScanOptions   `json:"yaraify_parameters,omitempty"`
	Metadata      *FileMetadata  `json:"metadata,omitempty"`
	StaticResults []YARAMatch    `json:"static_results,omitempty"`
	ClamAVResults []string       `json:"clamav_results,omitempty"`
	UnpackResults []UnpackedFile `json:"unpack_results,omitempty"`
}

// FileMetadata contains file metadata
type FileMetadata struct {
	FileName         string  `json:"file_name,omitempty"`
	FileSize         int     `json:"file_size,omitempty"`
	FileTypeMime     string  `json:"file_type_mime,omitempty"`
	FirstSeen        string  `json:"first_seen,omitempty"`
	LastSeen         string  `json:"last_seen,omitempty"`
	Sightings        int     `json:"sightings,omitempty"`
	UnpackedFilesCnt int     `json:"unpacked_files_cnt,omitempty"`
	SHA256Hash       string  `json:"sha256_hash,omitempty"`
	MD5Hash          string  `json:"md5_hash,omitempty"`
	SHA1Hash         string  `json:"sha1_hash,omitempty"`
	SHA3384          string  `json:"sha3_384,omitempty"`
	Imphash          *string `json:"imphash,omitempty"`
	SSDeep           *string `json:"ssdeep,omitempty"`
	TLSH             *string `json:"tlsh,omitempty"`
	Telfhash         *string `json:"telfhash,omitempty"`
	Gimphash         *string `json:"gimphash,omitempty"`
	DHashIcon        *string `json:"dhash_icon,omitempty"`
}

// YARAMatch represents a YARA rule match
type YARAMatch struct {
	RuleName    string  `json:"rule_name"`
	Author      *string `json:"author"`
	Description *string `json:"description"`
	Reference   *string `json:"reference"`
	YARAHubUUID *string `json:"yarahub_uuid"`
	TLP         string  `json:"tlp"`
}

// UnpackedFile represents an unpacked file from the scan
type UnpackedFile struct {
	UnpackedFileName    string      `json:"unpacked_file_name"`
	UnpackedMD5         string      `json:"unpacked_md5"`
	UnpackedSHA256      string      `json:"unpacked_sha256"`
	UnpackedYARAMatches []YARAMatch `json:"unpacked_yara_matches,omitempty"`
}

// HashLookupResponse represents the response from lookup_hash query
type HashLookupResponse struct {
	QueryStatus string          `json:"query_status"`
	Data        *HashLookupData `json:"data,omitempty"`
}

// HashLookupData contains lookup data for a hash
type HashLookupData struct {
	Metadata *FileMetadata `json:"metadata,omitempty"`
	Tasks    []TaskInfo    `json:"tasks,omitempty"`
}

// TaskInfo contains task information from hash lookup
type TaskInfo struct {
	TaskID           string         `json:"task_id"`
	TimeStamp        string         `json:"time_stamp"`
	FileName         string         `json:"file_name"`
	TaskParameters   *ScanOptions   `json:"task_parameters,omitempty"`
	UnpackedFilesCnt int            `json:"unpacked_files_cnt,omitempty"`
	ClamAVResults    []string       `json:"clamav_results,omitempty"`
	StaticResults    []YARAMatch    `json:"static_results,omitempty"`
	UnpackResults    []UnpackedFile `json:"unpack_results,omitempty"`
}

// YARAQueryResponse represents the response from get_yara query
type YARAQueryResponse struct {
	QueryStatus string       `json:"query_status"`
	QueryInfo   *QueryInfo   `json:"query_info,omitempty"`
	Data        []YARAResult `json:"data,omitempty"`
}

// QueryInfo contains query metadata
type QueryInfo struct {
	SearchScope string `json:"search_scope,omitempty"`
	ResultCount int    `json:"result_count,omitempty"`
	ResultMax   int    `json:"result_max,omitempty"`
}

// YARAResult represents a file matching a YARA rule
type YARAResult struct {
	SHA256Hash  string  `json:"sha256_hash"`
	FileSize    int     `json:"file_size"`
	MimeType    string  `json:"mime_type"`
	MD5Hash     string  `json:"md5_hash"`
	SHA1Hash    string  `json:"sha1_hash"`
	SHA3384Hash string  `json:"sha3_384_hash"`
	FirstSeen   string  `json:"first_seen"`
	LastSeen    *string `json:"last_seen"`
	Sightings   int     `json:"sightings"`
	Imphash     *string `json:"imphash"`
	SSDeep      *string `json:"ssdeep"`
	TLSH        *string `json:"tlsh"`
	Telfhash    *string `json:"telfhash"`
	Gimphash    *string `json:"gimphash"`
	DHashIcon   *string `json:"dhash_icon"`
}

// TaskListResponse represents the response from list_tasks query
type TaskListResponse struct {
	QueryStatus string     `json:"query_status"`
	Data        []TaskItem `json:"data,omitempty"`
}

// TaskItem represents a task in the list
type TaskItem struct {
	TaskID     string `json:"task_id"`
	TaskStatus string `json:"task_status"`
	MD5Hash    string `json:"md5_hash"`
	SHA256Hash string `json:"sha256_hash"`
	FileName   string `json:"file_name"`
}

// IdentifierResponse represents the response from generate_identifier query
type IdentifierResponse struct {
	QueryStatus string `json:"query_status"`
	Identifier  string `json:"identifier,omitempty"`
}

// GenericResponse represents a generic API response
type GenericResponse struct {
	QueryStatus string      `json:"query_status"`
	Data        interface{} `json:"data,omitempty"`
}

// ParseScanResponse parses scan submission response
func ParseScanResponse(data []byte) (*ScanResponse, error) {
	var resp ScanResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseTaskResultResponse parses task result response
func ParseTaskResultResponse(data []byte) (*TaskResultResponse, error) {
	var resp TaskResultResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseHashLookupResponse parses hash lookup response
func ParseHashLookupResponse(data []byte) (*HashLookupResponse, error) {
	var resp HashLookupResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseYARAQueryResponse parses YARA query response
func ParseYARAQueryResponse(data []byte) (*YARAQueryResponse, error) {
	var resp YARAQueryResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseTaskListResponse parses task list response
func ParseTaskListResponse(data []byte) (*TaskListResponse, error) {
	var resp TaskListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseIdentifierResponse parses identifier response
func ParseIdentifierResponse(data []byte) (*IdentifierResponse, error) {
	var resp IdentifierResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
