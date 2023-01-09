package DockerScan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateScan(t *testing.T) {
	jsonPath, _ := filepath.Abs("../testing/docker-repo.json")

	buffer, _ := os.ReadFile(jsonPath)

	jsonContent := string(buffer)

	result := CreateScan(jsonContent)

	if result.Ok {
		t.Fatalf("Result.Ok should be false as there are vulnerabilities in the report")
	}

	for _, vulnerability := range result.Vulnerabilities {
		fmt.Println(vulnerability.Title)
	}
}
