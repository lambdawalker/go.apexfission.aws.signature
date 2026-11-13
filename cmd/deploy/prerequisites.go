package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func checkVersions(r runner, github bool) error {
	requirements := []struct {
		Name         string
		Args         []string
		Major, Minor int
	}{{"go", []string{"version"}, 1, 26}, {"aws", []string{"--version"}, 2, 0}, {"pulumi", []string{"version"}, 3, 200}}
	if github {
		requirements = append(requirements, struct {
			Name         string
			Args         []string
			Major, Minor int
		}{"gh", []string{"--version"}, 2, 0})
	}
	re := regexp.MustCompile(`(?:go|v|/|version )?(\d+)\.(\d+)`)
	for _, req := range requirements {
		out, e := r.Run(req.Name, req.Args, nil, nil)
		if e != nil {
			return fmt.Errorf("install %s >= %d.%d and put it on PATH: %w", req.Name, req.Major, req.Minor, e)
		}
		match := re.FindStringSubmatch(string(out))
		if len(match) < 3 {
			return fmt.Errorf("cannot determine %s version from %q", req.Name, strings.TrimSpace(string(out)))
		}
		major, _ := strconv.Atoi(match[1])
		minor, _ := strconv.Atoi(match[2])
		if major < req.Major || (major == req.Major && minor < req.Minor) {
			return fmt.Errorf("%s >= %d.%d is required", req.Name, req.Major, req.Minor)
		}
	}
	return nil
}
