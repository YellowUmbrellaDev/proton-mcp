package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func pdfResult(n int) Result {
	return Result{
		Blob: bytes.Repeat([]byte{0xff}, n), Name: "factura 2026.pdf", MIMEType: "application/pdf",
		URI: "proton://mail/messages/MSG/attachments/ATT/factura%202026.pdf",
	}
}

func structured(t *testing.T, r *mcp.CallToolResult) map[string]any {
	t.Helper()
	raw, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSmallDownloadStaysInlineWithItsRealIdentity(t *testing.T) {
	res := toResult(pdfResult(1000), NewStore(), "ana")
	er, ok := res.Content[0].(*mcp.EmbeddedResource)
	if !ok {
		t.Fatalf("content = %T, want an embedded resource", res.Content[0])
	}
	if er.Resource.MIMEType != "application/pdf" || !strings.HasSuffix(er.Resource.URI, "/factura%202026.pdf") {
		t.Errorf("resource = %s %s", er.Resource.MIMEType, er.Resource.URI)
	}
	m := structured(t, res)
	if m["name"] != "factura 2026.pdf" || m["size"] != float64(1000) || m["mimeType"] != "application/pdf" || m["inline"] != true {
		t.Errorf("structuredContent = %v", m)
	}
}

func TestLargeDownloadIsLinkedNotInlined(t *testing.T) {
	store := NewStore()
	res := toResult(pdfResult(5_869_452), store, "ana")
	for _, c := range res.Content {
		if _, bad := c.(*mcp.EmbeddedResource); bad {
			t.Fatal("a 5.8 MB file came back inline")
		}
	}
	link, ok := res.Content[1].(*mcp.ResourceLink)
	if !ok || link.MIMEType != "application/pdf" || link.Name != "factura 2026.pdf" || *link.Size != 5_869_452 {
		t.Fatalf("link = %#v", res.Content[1])
	}
	if m := structured(t, res); m["inline"] != false || m["size"] != float64(5_869_452) {
		t.Errorf("structuredContent = %v", m)
	}
	if _, _, ok := store.Get("ana", link.URI); !ok {
		t.Error("the file was not kept for reading back")
	}
}

func TestLargeTextDownloadIsLinkedToo(t *testing.T) {
	r := Result{Text: strings.Repeat("a", InlineLimit+1), Name: "big.txt", MIMEType: "text/plain", URI: "proton://x/big.txt"}
	res := toResult(r, NewStore(), "ana")
	if _, ok := res.Content[1].(*mcp.ResourceLink); !ok {
		t.Fatalf("content = %#v", res.Content)
	}
}

func TestReadInPiecesReassemblesTheFile(t *testing.T) {
	store := NewStore()
	data := make([]byte, ChunkLimit*2+123)
	for i := range data {
		data[i] = byte(i)
	}
	if err := store.Put("ana", "proton://f/a.bin", "application/octet-stream", data); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for off := 0; off < len(data); off += ChunkLimit {
		r, err := store.readRange("ana", "proton://f/a.bin?offset="+itoa(off)+"&length="+itoa(ChunkLimit))
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, r.Contents[0].Blob...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("pieces do not add up to the file")
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestWholeReadOfLargeFileExplainsChunking(t *testing.T) {
	store := NewStore()
	_ = store.Put("ana", "proton://f/a.bin", "x/y", make([]byte, ChunkLimit+1))
	_, err := store.readRange("ana", "proton://f/a.bin")
	if err == nil || !strings.Contains(err.Error(), "offset=0") {
		t.Fatalf("err = %v", err)
	}
	if _, err := store.readRange("ana", "proton://f/a.bin?offset=-1"); err == nil {
		t.Fatal("negative offset accepted")
	}
}

func TestOneUserCannotReadAnothersDownload(t *testing.T) {
	store := NewStore()
	_ = store.Put("ana", "proton://f/a.bin", "x/y", []byte("secret"))
	if _, err := store.readRange("bob", "proton://f/a.bin"); err == nil {
		t.Fatal("bob read ana's file")
	}
}

func TestResourcesReadOverMCP(t *testing.T) {
	store := NewStore()
	_ = store.Put("ana", "proton://mail/m/attachments/a/x.pdf", "application/pdf", []byte("0123456789"))
	s := mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	addFileResources(s, store, func(context.Context) (Runner, error) { return Runner{Profile: "ana"}, nil })
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "proton://mail/m/attachments/a/x.pdf?offset=2&length=4"})
	if err != nil {
		t.Fatal(err)
	}
	if c := r.Contents[0]; string(c.Blob) != "2345" || c.MIMEType != "application/pdf" {
		t.Errorf("got %q %s", c.Blob, c.MIMEType)
	}
}

func TestDownloadURINamesTheFile(t *testing.T) {
	tool := Tool{Path: []string{"mail", "messages", "attachments", "download"}, Params: []Param{
		{Prop: "message", Positional: true}, {Prop: "attachment", Positional: true},
	}}
	got := downloadURI(tool, map[string]any{"message": "M1", "attachment": "A1"}, "a b.pdf")
	if want := "proton://mail/messages/attachments/M1/A1/a%20b.pdf"; got != want {
		t.Errorf("uri = %s, want %s", got, want)
	}
}
