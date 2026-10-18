package contacts

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/roman-16/proton-cli/internal/account/keys"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/vcard"
)

// exportDoer serves an address book of n contacts through the export endpoint, 50
// to a page, and records which pages were asked for.
type exportDoer struct {
	n         int
	reportTot bool
	cardFor   func(i int) map[string]any

	mu    sync.Mutex
	asked []int
}

func (d *exportDoer) Do(context.Context, proton.Request) (*proton.Response, error) { return nil, nil }

func (d *exportDoer) Decode(_ context.Context, r proton.Request, out any) error {
	var page int
	fmt.Sscan(r.Query.Get("Page"), &page)
	d.mu.Lock()
	d.asked = append(d.asked, page)
	d.mu.Unlock()
	var cs []map[string]any
	for i := page * contactsPageSize; i < d.n && i < (page+1)*contactsPageSize; i++ {
		cs = append(cs, map[string]any{"ID": fmt.Sprintf("c%04d", i), "Cards": []map[string]any{d.cardFor(i)}})
	}
	body := map[string]any{"Contacts": cs}
	if d.reportTot {
		body["Total"] = d.n
	}
	b, _ := json.Marshal(body)
	return json.Unmarshal(b, out)
}

func listOf(t *testing.T, d *exportDoer) []Contact {
	t.Helper()
	kr := testKeyRing(t)
	d.cardFor = func(i int) map[string]any {
		return signedCard(t, kr, vcard.BuildSigned(vcard.Signed{
			Name: fmt.Sprintf("n%04d", i), UID: fmt.Sprintf("u%d", i),
			Emails: []vcard.SignedEmail{{Address: fmt.Sprintf("n%d@example.com", i)}},
		}))
	}
	got, err := New(d, testKeys(&keys.Unlocked{UserKR: kr})).List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return got
}

func checkBook(t *testing.T, got []Contact, n int) {
	t.Helper()
	if len(got) != n {
		t.Fatalf("got %d contacts, want %d", len(got), n)
	}
	for i, c := range got {
		if want := fmt.Sprintf("c%04d", i); c.ID != want {
			t.Fatalf("contact %d is %s, want %s: pages must stay in the order Proton served them", i, c.ID, want)
		}
	}
}

// The first page says how big the book is, and the rest are asked for without
// waiting on each other; the result is still in Proton's order.
func TestListReadsEveryPageInOrderWhenTheTotalIsKnown(t *testing.T) {
	for _, n := range []int{0, 7, 50, 51, 100, 230} {
		d := &exportDoer{n: n, reportTot: true}
		checkBook(t, listOf(t, d), n)
		want := max(1, (n+contactsPageSize-1)/contactsPageSize)
		if len(d.asked) != want {
			t.Errorf("n=%d: asked pages %v, want %d requests", n, d.asked, want)
		}
	}
}

// Without a total the walk falls back to asking page after page until one is
// short, so nothing is lost.
func TestListFallsBackToSequentialPagesWithoutATotal(t *testing.T) {
	d := &exportDoer{n: 120}
	checkBook(t, listOf(t, d), 120)
	if len(d.asked) != 3 {
		t.Errorf("asked pages %v, want 3", d.asked)
	}
}
