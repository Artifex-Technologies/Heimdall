package verify

import (
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

func cred(text, role string) detect.Finding {
	return detect.Finding{DetectorID: "credential-shape", Severity: detect.SeverityCritical, Summary: "text contains what looks like a credential or secret",
		Event: detect.Event{Text: text, Fields: map[string]string{"role": role}}}
}

func TestExampleKeysAreRejectedAndRealOnesConfirmed(t *testing.T) {
	f := Apply(cred("my aws key is AKIAIOSFODNN7EXAMPLE and the secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "user"))
	if f.Event.Fields["verdict"] != "rejected" || f.Severity != detect.SeverityInfo || !strings.HasPrefix(f.Summary, "[rejected: only documentation examples") {
		t.Errorf("AWS's documented example: %+v", f)
	}
	for _, text := range []string{"password = ${DB_PASSWORD}", "secret_key = xxxxxxxxxxxxxxxx", "password: ********", "api_key=aaaaaaaaaaaaaaaaaaaa"} {
		if f := Apply(cred(text, "tool")); f.Event.Fields["verdict"] != "rejected" {
			t.Errorf("%q: %v", text, f.Event.Fields)
		}
	}
	for _, text := range []string{"AKIAZ3MQ7LXK2PQ8WN4T", "api_key=Zq8vN2pLxR7tY4kW9mB3cD6f", "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5", "password: hunter2!x", "AKIAIOSFODNN7EXAMPLE then AKIAZ3MQ7LXK2PQ8WN4T"} {
		f := Apply(cred(text, "tool"))
		if f.Event.Fields["verdict"] != "confirmed" || f.Severity != detect.SeverityCritical {
			t.Errorf("%q: %v %s", text, f.Event.Fields, f.Severity)
		}
	}
}

func TestOtherVerdicts(t *testing.T) {
	in := Apply(detect.Finding{DetectorID: "inbound", Severity: detect.SeverityWarning, Event: detect.Event{Fields: map[string]string{"spoofable": "1"}}})
	if in.Event.Fields["verdict"] != "needs_validation" || in.Severity != detect.SeverityWarning {
		t.Errorf("scan: %v", in)
	}
	inj := Apply(detect.Finding{DetectorID: "injection-phrase", Severity: detect.SeverityCritical, Event: detect.Event{Fields: map[string]string{"role": "tool"}}})
	if inj.Event.Fields["verdict"] != "confirmed" {
		t.Errorf("injection in a tool result: %v", inj)
	}
	orig := map[string]string{"role": "user"}
	u := Apply(detect.Finding{DetectorID: "injection-phrase", Severity: detect.SeverityCritical, Event: detect.Event{Fields: orig}})
	if u.Event.Fields["verdict"] != "needs_validation" || u.Severity != detect.SeverityCritical {
		t.Errorf("injection in the person's message: %v", u)
	}
	if _, ok := orig["verdict"]; ok {
		t.Error("the event's own fields were changed")
	}
	other := Apply(detect.Finding{DetectorID: "file-integrity", Severity: detect.SeverityWarning, Event: detect.Event{}})
	if other.Event.Fields["verdict"] != "" {
		t.Error("a verdict for a detector no check covers")
	}
}
