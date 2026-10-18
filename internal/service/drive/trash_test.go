package drive

import (
	"context"
	"reflect"
	"testing"
)

// Proton names at most fifty links per request, so a large trash is asked about
// a batch at a time rather than all at once or one by one.
func TestChunkCutsIntoBatches(t *testing.T) {
	ids := make([]string, 0, 120)
	for i := 0; i < 120; i++ {
		ids = append(ids, string(rune('a'+i%26)))
	}
	batches := chunk(ids, linkBatch)
	if len(batches) != 3 {
		t.Fatalf("cut 120 ids into %d batches, want 3", len(batches))
	}
	sizes := []int{len(batches[0]), len(batches[1]), len(batches[2])}
	if !reflect.DeepEqual(sizes, []int{50, 50, 20}) {
		t.Errorf("batch sizes are %v, want [50 50 20]", sizes)
	}
	var seen int
	for _, batch := range batches {
		seen += len(batch)
	}
	if seen != len(ids) {
		t.Errorf("batches hold %d ids, want %d", seen, len(ids))
	}
}

func TestChunkOfNothingIsNoRequests(t *testing.T) {
	if got := chunk(nil, linkBatch); got != nil {
		t.Errorf("chunk(nil) = %v, want no batches", got)
	}
}

// Asking what links are is a question, however it is sent: a dry run has to be
// able to look at an album or a photo to say what it would do to it.
func TestTheLinkMetadataQuestionIsAReadDespiteBeingAPost(t *testing.T) {
	tr := newTree(t, shareTypeDevice, protonFolder, "Work laptop")
	s, doer := tr.service(map[string]string{"POST /drive/shares/" + testShareID + "/links/fetch_metadata": `{"Code":1000,"Links":[]}`})
	if _, err := s.linkMetadata(context.Background(), testShareID, []string{"a-link"}); err != nil {
		t.Fatal(err)
	}
	req := doer.last()
	if req.Method != "POST" || !req.Reads {
		t.Errorf("%s %s does not say it only reads, so --dry-run would refuse it", req.Method, req.Path)
	}
}
