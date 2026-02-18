package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestApplyDelta_BasicReplace(t *testing.T) {
	original := []byte(`{"version":3,"deployment":{"resources":[{"urn":"old-resource"}]}}`)

	// Edit: replace "old-resource" with "new-resource"
	// "old-resource" starts at offset 48, ends at 60
	edits := []textEdit{
		{
			Span: textSpan{
				Start: textPoint{Line: 1, Column: 0, Offset: 48},
				End:   textPoint{Line: 1, Column: 0, Offset: 60},
			},
			NewText: "new-resource",
		},
	}

	deltaJSON, _ := json.Marshal(edits)
	result, err := applyDelta(original, string(deltaJSON))
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"version":3,"deployment":{"resources":[{"urn":"new-resource"}]}}`
	if string(result) != expected {
		t.Fatalf("expected:\n%s\ngot:\n%s", expected, string(result))
	}
}

func TestApplyDelta_MultipleEdits(t *testing.T) {
	original := []byte(`AAABBBCCC`)

	// Replace BBB (offset 3-6) with DDDD, and CCC (offset 6-9) with EE
	edits := []textEdit{
		{
			Span: textSpan{
				Start: textPoint{Offset: 3},
				End:   textPoint{Offset: 6},
			},
			NewText: "DDDD",
		},
		{
			Span: textSpan{
				Start: textPoint{Offset: 6},
				End:   textPoint{Offset: 9},
			},
			NewText: "EE",
		},
	}

	deltaJSON, _ := json.Marshal(edits)
	result, err := applyDelta(original, string(deltaJSON))
	if err != nil {
		t.Fatal(err)
	}

	expected := "AAADDDDEE"
	if string(result) != expected {
		t.Fatalf("expected %q, got %q", expected, string(result))
	}
}

func TestApplyDelta_Insert(t *testing.T) {
	original := []byte(`AACCC`)

	// Insert BB at offset 2 (start == end means pure insertion)
	edits := []textEdit{
		{
			Span: textSpan{
				Start: textPoint{Offset: 2},
				End:   textPoint{Offset: 2},
			},
			NewText: "BB",
		},
	}

	deltaJSON, _ := json.Marshal(edits)
	result, err := applyDelta(original, string(deltaJSON))
	if err != nil {
		t.Fatal(err)
	}

	expected := "AABBCCC"
	if string(result) != expected {
		t.Fatalf("expected %q, got %q", expected, string(result))
	}
}

func TestApplyDelta_Delete(t *testing.T) {
	original := []byte(`AABBBCC`)

	// Delete BBB (offset 2-5, empty NewText)
	edits := []textEdit{
		{
			Span: textSpan{
				Start: textPoint{Offset: 2},
				End:   textPoint{Offset: 5},
			},
			NewText: "",
		},
	}

	deltaJSON, _ := json.Marshal(edits)
	result, err := applyDelta(original, string(deltaJSON))
	if err != nil {
		t.Fatal(err)
	}

	expected := "AACC"
	if string(result) != expected {
		t.Fatalf("expected %q, got %q", expected, string(result))
	}
}

func TestApplyDelta_EmptyEdits(t *testing.T) {
	original := []byte(`no changes`)
	result, err := applyDelta(original, `[]`)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(original) {
		t.Fatalf("expected no change, got %q", string(result))
	}
}

func TestApplyDelta_HashVerification(t *testing.T) {
	// Simulate the full delta checkpoint flow:
	// 1. Original state
	// 2. Apply delta
	// 3. Verify SHA-256 matches
	original := []byte(`{"version":3,"deployment":{"resources":[]}}`)
	newState := []byte(`{"version":3,"deployment":{"resources":[{"urn":"new"}]}}`)

	// Find the exact offset of "[]" in the original.
	// {"version":3,"deployment":{"resources":[]}}
	//                                       ^^ offset 39-41
	start := 39
	end := 41
	if string(original[start:end]) != "[]" {
		t.Fatalf("bad offset calculation: got %q at [%d:%d]", original[start:end], start, end)
	}

	edits := []textEdit{
		{
			Span: textSpan{
				Start: textPoint{Offset: start},
				End:   textPoint{Offset: end},
			},
			NewText: `[{"urn":"new"}]`,
		},
	}

	deltaJSON, _ := json.Marshal(edits)
	result, err := applyDelta(original, string(deltaJSON))
	if err != nil {
		t.Fatal(err)
	}

	if string(result) != string(newState) {
		t.Fatalf("expected:\n%s\ngot:\n%s", newState, result)
	}

	// Verify hash matches.
	expectedHash := sha256.Sum256(newState)
	actualHash := sha256.Sum256(result)
	if hex.EncodeToString(expectedHash[:]) != hex.EncodeToString(actualHash[:]) {
		t.Fatal("hash mismatch")
	}
}

func TestApplyDelta_OutOfBounds(t *testing.T) {
	original := []byte(`short`)

	edits := []textEdit{
		{
			Span: textSpan{
				Start: textPoint{Offset: 0},
				End:   textPoint{Offset: 100}, // past end
			},
			NewText: "x",
		},
	}

	deltaJSON, _ := json.Marshal(edits)
	_, err := applyDelta(original, string(deltaJSON))
	if err == nil {
		t.Fatal("expected error for out-of-bounds edit")
	}
}
