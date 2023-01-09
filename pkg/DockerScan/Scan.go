package DockerScan

import (
	"encoding/json"
	"time"
)

type SemVer struct {
	Vulnerable []string `json:"vulnerable"`
}

type Insights struct {
	TriageAdvice interface{} `json:"triageAdvice"`
}

type Reference struct {
	Url   string `json:"url"`
	Title string `json:"title"`
}

type CvssDetail struct {
	Assigner         string    `json:"assigner"`
	Severity         string    `json:"severity"`
	CvssV3Vector     string    `json:"cvssV3Vector"`
	CvssV3BaseScore  float64   `json:"cvssV3BaseScore"`
	ModificationTime time.Time `json:"modificationTime"`
}

type Advice struct {
	Message string `json:"message"`
	Bold    bool   `json:"bold,omitempty"`
}

type BaseImageRemediation struct {
	Code              string   `json:"code"`
	BaseImageOutdated bool     `json:"baseImageOutdated"`
	Advice            []Advice `json:"advice"`
}

type Docker struct {
	BaseImage            string               `json:"baseImage"`
	BaseImageRemediation BaseImageRemediation `json:"baseImageRemediation"`
}

type Identifiers struct {
	CVE         []string `json:"CVE"`
	CWE         []string `json:"CWE"`
	ALTERNATIVE []string `json:"ALTERNATIVE"`
}

type Vulnerability struct {
	Id                    string        `json:"id"`
	Cpes                  []interface{} `json:"cpes"`
	Title                 string        `json:"title"`
	CVSSv3                *string       `json:"CVSSv3"`
	Credit                []string      `json:"credit"`
	Semver                SemVer        `json:"semver"`
	Exploit               string        `json:"exploit"`
	Patches               []interface{} `json:"patches"`
	Insights              Insights      `json:"insights"`
	Language              string        `json:"language"`
	Severity              string        `json:"severity"`
	CvssScore             *float64      `json:"cvssScore"`
	Malicious             bool          `json:"malicious"`
	References            []Reference   `json:"references"`
	CvssDetails           []CvssDetail  `json:"cvssDetails"`
	Description           string        `json:"description"`
	Identifiers           Identifiers   `json:"identifiers"`
	NvdSeverity           *string       `json:"nvdSeverity"`
	PackageName           string        `json:"packageName"`
	CreationTime          time.Time     `json:"creationTime"`
	DisclosureTime        *time.Time    `json:"disclosureTime"`
	PackageManager        string        `json:"packageManager"`
	PublicationTime       time.Time     `json:"publicationTime"`
	ModificationTime      time.Time     `json:"modificationTime"`
	SocialTrendAlert      bool          `json:"socialTrendAlert"`
	RelativeImportance    interface{}   `json:"relativeImportance"`
	SeverityWithCritical  string        `json:"severityWithCritical"`
	From                  []string      `json:"from"`
	UpgradePath           []interface{} `json:"upgradePath"`
	IsUpgradable          bool          `json:"isUpgradable"`
	IsPatchable           bool          `json:"isPatchable"`
	Name                  string        `json:"name"`
	Version               string        `json:"version"`
	NearestFixedInVersion string        `json:"nearestFixedInVersion"`
	DockerBaseImage       string        `json:"dockerBaseImage"`
	DockerfileInstruction string        `json:"dockerfileInstruction,omitempty"`
}

type Scan struct {
	Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
	Ok                 bool            `json:"ok"`
	DependencyCount    int             `json:"dependencyCount"`
	Policy             string          `json:"policy"`
	IsPrivate          bool            `json:"isPrivate"`
	LicensesPolicy     interface{}     `json:"licensesPolicy"`
	PackageManager     string          `json:"packageManager"`
	Docker             Docker          `json:"docker"`
	Summary            string          `json:"summary"`
	FilesystemPolicy   bool            `json:"filesystemPolicy"`
	UniqueCount        int             `json:"uniqueCount"`
	ProjectName        string          `json:"projectName"`
	Platform           string          `json:"platform"`
	HasUnknownVersions bool            `json:"hasUnknownVersions"`
	Path               string          `json:"path"`
}

func CreateScan(jsonString string) *Scan {
	scan := new(Scan)
	_ = json.Unmarshal([]byte(jsonString), &scan)

	return scan
}
