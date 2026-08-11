// Package main provides a CLI tool for parsing and summarising lcov coverage reports.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// FileRecord holds coverage statistics for one source file.
type FileRecord struct {
	Path          string
	LinesFound    int
	LinesHit      int
	BranchesFound int
	BranchesHit   int
	FuncsFound    int
	FuncsHit      int
}

// LinePct returns the line coverage percentage (0-100).
func (r *FileRecord) LinePct() float64 {
	if r.LinesFound == 0 {
		return 0.0
	}
	return float64(r.LinesHit) / float64(r.LinesFound) * 100.0
}

// BranchPct returns the branch coverage percentage (0-100).
func (r *FileRecord) BranchPct() float64 {
	if r.BranchesFound == 0 {
		return 0.0
	}
	return float64(r.BranchesHit) / float64(r.BranchesFound) * 100.0
}

// ParseLcov reads an lcov.info file and returns one FileRecord per SF block.
func ParseLcov(path string) ([]FileRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var records []FileRecord
	var cur *FileRecord

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		tag, val, _ := strings.Cut(line, ":")
		val = strings.TrimSpace(val)

		switch tag {
		case "SF":
			cur = &FileRecord{Path: val}
		case "LF":
			if cur != nil {
				cur.LinesFound, _ = strconv.Atoi(val)
			}
		case "LH":
			if cur != nil {
				cur.LinesHit, _ = strconv.Atoi(val)
			}
		case "BRF":
			if cur != nil {
				cur.BranchesFound, _ = strconv.Atoi(val)
			}
		case "BRH":
			if cur != nil {
				cur.BranchesHit, _ = strconv.Atoi(val)
			}
		case "FNF":
			if cur != nil {
				cur.FuncsFound, _ = strconv.Atoi(val)
			}
		case "FNH":
			if cur != nil {
				cur.FuncsHit, _ = strconv.Atoi(val)
			}
		case "end_of_record":
			if cur != nil {
				records = append(records, *cur)
				cur = nil
			}
		}
	}
	return records, scanner.Err()
}

func printSummary(records []FileRecord) {
	const fmtHdr = "%-40s  %10s  %7s  %10s\n"
	const fmtRow = "%-40s  %4d/%-4d   %5.1f%%  %4d/%-4d\n"
	sep := strings.Repeat("-", 70)

	fmt.Printf(fmtHdr, "File", "Lines", "Cov%", "Branches")
	fmt.Println(sep)

	var totalLF, totalLH, totalBRF, totalBRH int
	for _, r := range records {
		name := r.Path
		if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
			name = name[idx+1:]
		}
		fmt.Printf(fmtRow, name, r.LinesHit, r.LinesFound, r.LinePct(),
			r.BranchesHit, r.BranchesFound)
		totalLF += r.LinesFound
		totalLH += r.LinesHit
		totalBRF += r.BranchesFound
		totalBRH += r.BranchesHit
	}

	fmt.Println(sep)
	overall := 0.0
	if totalLF > 0 {
		overall = float64(totalLH) / float64(totalLF) * 100.0
	}
	fmt.Printf(fmtRow, "TOTAL", totalLH, totalLF, overall, totalBRH, totalBRF)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: coverage_parser <lcov.info>")
		os.Exit(1)
	}

	records, err := ParseLcov(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printSummary(records)
}
