package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := &TransferRequest{TransferID: "x", Mode: ModeFile, Name: "a.py", Size: 42, SHA256: "ab"}
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := Expect[*TransferRequest](&buf)
	if err != nil {
		t.Fatal(err)
	}
	if *out != *in {
		t.Fatalf("got %+v", out)
	}
}

func TestExpectWrongType(t *testing.T) {
	var buf bytes.Buffer
	WriteMsg(&buf, &HelloAck{Version: 1})
	if _, err := Expect[*TransferRequest](&buf); err == nil {
		t.Fatal("expected type error")
	}
}

func TestExpectSurfacesRemoteError(t *testing.T) {
	var buf bytes.Buffer
	WriteMsg(&buf, &Error{Message: "nope"})
	_, err := Expect[*Hello](&buf)
	if !IsRemote(err) {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(MaxFrame+1))
	if _, err := ReadMsg(&buf); err == nil {
		t.Fatal("expected error")
	}
}

func TestZeroLengthFrameRejected(t *testing.T) {
	if _, err := ReadMsg(bytes.NewReader([]byte{0, 0, 0, 0})); err == nil {
		t.Fatal("expected error")
	}
}

func TestUnknownTypeAndGarbage(t *testing.T) {
	body := []byte(`{"type":"bogus","body":{}}`)
	frame := append([]byte{0, 0, 0, byte(len(body))}, body...)
	if _, err := ReadMsg(bytes.NewReader(frame)); err == nil {
		t.Fatal("expected unknown type error")
	}
	frame = append([]byte{0, 0, 0, 3}, []byte("{{{")...)
	if _, err := ReadMsg(bytes.NewReader(frame)); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestTruncatedFrame(t *testing.T) {
	if _, err := ReadMsg(bytes.NewReader([]byte{0, 0, 0, 10, 1})); err == nil {
		t.Fatal("expected error")
	}
}

func TestNegotiate(t *testing.T) {
	if v, err := Negotiate([]int{1, 2}, []int{2, 3}); err != nil || v != 2 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	if _, err := Negotiate([]int{1}, []int{2}); err == nil {
		t.Fatal("expected no common version")
	}
}
