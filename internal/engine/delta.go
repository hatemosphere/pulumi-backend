package engine

import (
	"encoding/json"
	"fmt"
	"sort"
)

// textEdit matches the gotextdiff.TextEdit JSON structure used by the Pulumi CLI.
// The CLI computes edits using the pgavlin/diff/lcs library on spanned deployment JSON,
// then serializes them as a JSON array of TextEdit with byte-offset spans.
type textEdit struct {
	Span    textSpan `json:"Span"`
	NewText string   `json:"NewText"`
}

type textSpan struct {
	URI   string    `json:"uri"`
	Start textPoint `json:"start"`
	End   textPoint `json:"end"`
}

type textPoint struct {
	Line   int `json:"line"`
	Column int `json:"column"`
	Offset int `json:"offset"`
}

// applyDelta applies a set of text edits (byte-offset replacements) to the original
// deployment JSON to produce the new deployment JSON. The delta is a JSON array of
// TextEdit structs where each edit replaces bytes [Start.Offset, End.Offset) with NewText.
//
// Edits must be non-overlapping.
func applyDelta(original []byte, delta string) ([]byte, error) {
	var edits []textEdit
	if err := json.Unmarshal([]byte(delta), &edits); err != nil {
		return nil, fmt.Errorf("unmarshal delta edits: %w", err)
	}

	if len(edits) == 0 {
		return original, nil
	}

	// Sort edits by start offset ascending.
	sort.Slice(edits, func(i, j int) bool {
		return edits[i].Span.Start.Offset < edits[j].Span.Start.Offset
	})

	// Check for overlaps and out of bounds.
	// Also calculate the total size of the result to allocate once.
	totalSize := len(original)
	lastEnd := 0
	for _, edit := range edits {
		start := edit.Span.Start.Offset
		end := edit.Span.End.Offset

		if start < lastEnd {
			return nil, fmt.Errorf("overlapping edit at offset %d (previous end %d)", start, lastEnd)
		}
		if start < 0 || end < start || end > len(original) {
			return nil, fmt.Errorf("edit out of bounds: start=%d end=%d len=%d", start, end, len(original))
		}

		// Subtract the removed range, add the new text length.
		totalSize -= (end - start)
		totalSize += len(edit.NewText)
		lastEnd = end
	}

	// Allocate result buffer.
	result := make([]byte, 0, totalSize)
	cursor := 0

	for _, edit := range edits {
		start := edit.Span.Start.Offset
		end := edit.Span.End.Offset

		// Append unchanged part from cursor to start of edit.
		result = append(result, original[cursor:start]...)
		// Append replacement text.
		result = append(result, []byte(edit.NewText)...)
		// Advance cursor to end of replaced range.
		cursor = end
	}

	// Append remaining part of original.
	result = append(result, original[cursor:]...)

	return result, nil
}
