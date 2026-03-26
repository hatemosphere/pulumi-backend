package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

type matrixFile struct {
	Source struct {
		VersionsPage  string `json:"versionsPage"`
		CurrentStable string `json:"currentStable"`
		CheckedDate   string `json:"checkedDate"`
	} `json:"source"`
	TestPattern string                  `json:"testPattern"`
	Versions    []string                `json:"versions"`
	Results     map[string]matrixResult `json:"results"`
}

type matrixResult struct {
	Status string `json:"status"`
}

func main() {
	const matrixPath = "tests/testdata/cli_compat_matrix.json"

	matrix, err := loadMatrix(matrixPath)
	if err != nil {
		fail("load matrix", err)
	}

	cacheDir := filepath.Join(".cache", "pulumi-cli")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		fail("mkdir cache", err)
	}

	for _, version := range matrix.Versions {
		binPath, err := ensurePulumi(version, cacheDir)
		if err != nil {
			matrix.Results[version] = matrixResult{Status: "download-failed"}
			fmt.Fprintf(os.Stderr, "download %s: %v\n", version, err)
			continue
		}

		status := runCompatibilitySuite(binPath, matrix.TestPattern)
		matrix.Results[version] = matrixResult{Status: status}
		fmt.Printf("%s => %s\n", version, status)
	}

	if err := writeMatrix(matrixPath, matrix); err != nil {
		fail("write matrix", err)
	}
	if err := updateReadme("README.md", matrix); err != nil {
		fail("update readme", err)
	}
}

func loadMatrix(path string) (*matrixFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m matrixFile
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Results == nil {
		m.Results = map[string]matrixResult{}
	}
	return &m, nil
}

func writeMatrix(path string, m *matrixFile) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644) //nolint:gosec // committed testdata file
}

func ensurePulumi(version, cacheDir string) (string, error) {
	destDir := filepath.Join(cacheDir, version)
	binPath := filepath.Join(destDir, "pulumi", "pulumi")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if _, err := os.Stat(binPath); err == nil {
		return binPath, nil
	}

	url := fmt.Sprintf("https://get.pulumi.com/releases/sdk/pulumi-v%s-%s-%s.tar.gz", version, platformOS(), platformArch())
	resp, err := http.Get(url) //nolint:gosec // version URL is generated from pinned matrix entries
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		target := filepath.Join(destDir, hdr.Name) //nolint:gosec // validated against clean destination prefix below
		cleanDestDir := filepath.Clean(destDir) + string(os.PathSeparator)
		cleanTarget := filepath.Clean(target)
		if !strings.HasPrefix(cleanTarget, cleanDestDir) {
			return "", fmt.Errorf("archive path escapes destination: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			mode := os.FileMode(hdr.Mode & 0o777)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, mode)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(f, tr); err != nil { //nolint:gosec // trusted Pulumi release archive
				_ = f.Close()
				return "", err
			}
			if err := f.Close(); err != nil {
				return "", err
			}
		}
	}

	return binPath, nil
}

func runCompatibilitySuite(binPath, pattern string) string {
	cmd := exec.Command("go", "test", "./tests", "-run", pattern, "-count=1")
	cmd.Env = append(os.Environ(), "PULUMI_CLI_PATH="+binPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "failing"
	}
	return "compatible"
}

func updateReadme(path string, m *matrixFile) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	const start = "<!-- cli-compat:start -->"
	const end = "<!-- cli-compat:end -->"
	section := renderReadmeSection(m)

	content := string(data)
	if strings.Contains(content, start) && strings.Contains(content, end) {
		before, after, found := strings.Cut(content, start)
		if !found {
			return errors.New("start marker not found")
		}
		_, tail, found := strings.Cut(after, end)
		if !found {
			return errors.New("end marker not found")
		}
		content = before + start + "\n" + section + "\n" + end + tail
	} else {
		content = strings.Replace(content, "# pulumi-backend\n\n", "# pulumi-backend\n\n"+start+"\n"+section+"\n"+end+"\n\n", 1)
	}

	return os.WriteFile(path, []byte(content), 0o644) //nolint:gosec // updating README
}

func renderReadmeSection(m *matrixFile) string {
	var b strings.Builder
	fmt.Fprintln(&b, "## CLI Compatibility")
	fmt.Fprintf(&b, "Tested smoke suite `%s` against Pulumi CLI releases. Current stable at check time: `%s`.\n\n",
		m.TestPattern, m.Source.CurrentStable)

	versions := slices.Clone(m.Versions)
	slices.Sort(versions)
	for _, version := range versions {
		status := m.Results[version].Status
		color := "lightgrey"
		label := "untested"
		switch status {
		case "compatible":
			color = "brightgreen"
			label = "compatible"
		case "failing":
			color = "red"
			label = "failing"
		case "download-failed":
			color = "orange"
			label = "download_failed"
		}
		fmt.Fprintf(&b, "[![Pulumi CLI %s](https://img.shields.io/badge/Pulumi_CLI_%s-%s-%s)](https://github.com/pulumi/pulumi/releases/tag/v%s)\n",
			version, strings.ReplaceAll(version, "-", "--"), label, color, version)
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Version | Status |")
	fmt.Fprintln(&b, "|---|---|")
	for _, version := range versions {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", version, m.Results[version].Status)
	}
	fmt.Fprintf(&b, "\nSource: %s (checked %s).\n", m.Source.VersionsPage, m.Source.CheckedDate)
	return strings.TrimRight(b.String(), "\n")
}

func platformOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		panic("unsupported os: " + runtime.GOOS)
	}
}

func platformArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported arch: " + runtime.GOARCH)
	}
}

func fail(action string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", action, err)
	os.Exit(1)
}
