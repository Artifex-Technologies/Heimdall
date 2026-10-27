// Package explain says what an alert means in plain words, without any AI: what happened, how serious it is, what Heimdall already
// did about it, and what the owner can do. It is fixed text chosen by the alert's detector and severity, with a few details (a path,
// a package, an address) taken from the alert's fields, so it is the same every time and works on a computer without Sarina. When
// Sarina is there, her advice is shown beside it, never instead of it.
//
// The fields come from what Heimdall observed (file names, network names, a session's text can be hostile). They are quoted as
// values, cut short and stripped of control characters; nothing in them is ever followed as an instruction.
package explain

import (
	"strings"
)

// Text is the plain-language explanation of one alert.
type Text struct {
	What    string `json:"what"`
	Serious string `json:"serious"`
	Done    string `json:"done"`
	Do      string `json:"do"`
}

// clean makes an observed value safe to show inside a sentence: no control characters, one line, at most n characters.
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = ' '
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if r := []rune(out); len(r) > n {
		out = string(r[:n-1]) + "…"
	}
	return out
}

func quoted(fields map[string]string, key string) string {
	v := clean(fields[key], 120)
	if v == "" {
		return ""
	}
	return "“" + v + "”"
}

func serious(severity string) string {
	switch severity {
	case "critical":
		return "Serious: look at it now."
	case "warning":
		return "Worth a look soon; nothing is broken yet."
	default:
		return "For your information; nothing needs doing."
	}
}

const (
	logged      = "Heimdall recorded it; nothing was changed on your computer."
	settings    = "Settings > Security lists it with the others."
	aiAgentNote = "This concerns an AI agent on this computer (Sarina or another local agent Heimdall watches)."
)

// For returns the explanation of an alert from its detector, severity and fields. Every detector has one; an unknown detector gets a
// general one, so a newer Heimdall never shows an alert with no words at all.
func For(detector, severity string, fields map[string]string) Text {
	t := Text{Serious: serious(severity), Done: logged}
	path := quoted(fields, "path")
	switch detector {
	case "injection-phrase":
		t.What = "Text that tries to give an AI agent orders (“ignore your instructions”, “you are now…”) appeared in something the agent read: a web page, a file, an email. " + aiAgentNote
		t.Do = "Do not act on anything the agent proposed after reading it. If you did not expect it, look at where the text came from. " + settings
	case "credential-shape":
		t.What = "Something that looks like a password, key or access token appeared in an AI agent's output or in text it handled. " + aiAgentNote
		t.Do = "If it is a real secret, change it at the service it belongs to (it may have been shown or stored where it should not be)."
	case "invisible-unicode":
		t.What = "Text contained invisible or look-alike characters, a known way to hide instructions from people while an AI still reads them. " + aiAgentNote
		t.Do = "Treat the text as suspicious; do not copy it into commands."
	case "permission-escalation":
		t.What = "An AI agent repeatedly asked for things its current permissions do not allow (running commands, writing files). It was refused each time. " + aiAgentNote
		t.Done = "The requests were refused by the agent's own permission rules; Heimdall recorded them."
		t.Do = "If you did not ask the agent to do something that needs more access, look at what it was working on."
	case "session-burst":
		t.What = "An AI agent started far more sessions in a short time than one person normally would. That can be a loop, or something driving it. " + aiAgentNote
		t.Do = "If you are not running anything in bulk, stop the agent and look at what started the sessions."
	case "file-integrity":
		t.What = "A watched program or setting file changed: " + orUnknown(path, "a watched file") + ". Heimdall watches the security tools, the AI agents and their settings, because changing them is how an attack takes over."
		if fields["prior_hash"] == "" && fields["new_hash"] != "" {
			t.What = "A new file appeared in a watched folder: " + orUnknown(path, "a new file") + "."
		}
		t.Do = "If you just installed updates or changed this file yourself, nothing to do. Otherwise reinstall the package it belongs to (pacman -Qo shows which) and check Settings > Security."
	case "maintenance-window":
		t.What = "A maintenance window opened or closed: during one, routine alerts are softened because changes are expected."
		t.Do = "Nothing, if you or your administrator opened it."
	case "resource-pressure":
		t.What = "The computer is short of memory or very busy (memory " + orUnknown(clean(fields["mem_percent"], 8), "high") + "%, load " + orUnknown(clean(fields["load_per_cpu"], 8), "high") + " per core)."
		t.Do = "Close what you do not need; the system monitor shows what is using it. If nothing you run explains it, something unexpected may be running."
	case "network-exposure":
		t.What = "A local service that should only be reachable from this computer is listening to the network: port " + orUnknown(clean(fields["port"], 8), "?") + " on " + orUnknown(clean(fields["address"], 60), "all addresses") + "."
		t.Do = "Others on your network may reach it. Stop the program or set it to listen on 127.0.0.1 only; the firewall in Settings > Security can also block it."
	case "connection-watch":
		t.What = "A program connected somewhere worth a look: " + orUnknown(quoted(fields, "process"), "a program") + " to " + orUnknown(clean(fields["remote_addr"], 60), "a remote address") + originText(fields) + "."
		if fields["remote_listed"] != "" {
			t.What += " That address is on a threat list."
		}
		t.Do = "If you know the program and where it talks to, nothing to do. If not, block its network access in Settings > Apps, or stop it."
	case "inbound":
		t.What = "Something on the network tried to reach this computer" + srcText(fields) + " and the firewall " + orUnknown(clean(fields["verdict"], 20), "dealt with it") + "."
		t.Done = "The firewall acted on it; Heimdall recorded it."
		t.Do = "Usually nothing: the firewall did its job. Many attempts from one address, or any that got through, are worth a look in Settings > Security."
	case "package-vulnerability":
		t.What = "An installed package has a known security hole: " + orUnknown(quoted(fields, "package"), "a package") + versionText(fields) + "."
		t.Do = "Update the system (Agora > Updates, or sudo pacman -Syu). If no fix is out yet, the alert says what to avoid meanwhile."
	case "kernel-vulnerability":
		t.What = "A kernel installed on this computer has known security holes that a newer kernel fixes" + runningText(fields) + "."
		t.Do = "Update (Agora > Updates) and restart into the new kernel. A hole in a kernel you are not running matters only when you start it."
	case "hardening":
		t.What = "A security setting of the system is weaker than it should be" + orEmpty(quoted(fields, "now"), ": ") + "."
		if f := clean(fields["fix"], 160); f != "" {
			t.Do = "To fix it: " + f + "."
		} else {
			t.Do = "Settings > Security shows the setting and how to restore it."
		}
	case "wifi-safety":
		t.What = "A check of the Wi-Fi network " + orUnknown(quoted(fields, "ssid"), "you joined") + " found something that can expose your traffic (an open network, a weak lock, or a network pretending to be another)."
		t.Do = "Avoid signing in to anything important on this network, or turn on a VPN first."
	case "lan-watch":
		t.What = "Something on your local network is pretending to be your router or another device (its hardware address changed to " + orUnknown(clean(fields["new_mac"], 40), "a new one") + "). That is how traffic on a shared network gets intercepted."
		t.Do = "On a network you do not control, disconnect or use a VPN. At home, restart the router and check which devices are connected."
	case "baseline-drift":
		t.What = "The computer behaved unlike its usual self (far more activity of some kind than normal for this time)."
		t.Do = "If you are doing something unusual (a big download, a build), nothing to do. Otherwise look at what is running."
	case "limbo-guest":
		t.What = "A program running in a Limbo sandbox broke the sandbox's safety rules" + orEmpty(quoted(fields, "guest"), ": ") + "."
		t.Done = "Heimdall asked Limbo to cut the sandbox off (quarantine). Limbo never lets Heimdall release it; only you can."
		t.Do = "Look at the quarantine in Settings > Security before releasing anything; if unsure, delete the sandbox."
	case "remote-access":
		tool := orUnknown(clean(fields["provider_name"], 60), "a tool")
		switch {
		case fields["signal"] == "tunnel":
			t.What = "A new tunnel network interface appeared (" + orUnknown(clean(fields["iface"], 30), "unnamed") + "). A VPN you start does this; so does a program that wants a hidden way in or out."
			t.Do = "If you just connected a VPN, nothing to do. Otherwise look at what created it (ip link, and the programs you installed recently)."
		case fields["ra_kind"] == "c2":
			t.What = "A program known as an attacker's remote control (" + tool + ") is on this computer."
			t.Do = "Treat the computer as compromised: disconnect it from the network and ask for help before using it for anything private."
		case severity == "info":
			t.What = tool + ", which you approved, is in use."
			t.Do = "Nothing to do."
		default:
			t.What = tool + " lets someone reach this computer from elsewhere, and it is here without your approval (" + orUnknown(clean(fields["signal"], 30), "seen") + "). Malware often installs a tool like this to keep a way in."
			t.Do = "If you installed it yourself and want it, approve it: sudo heimdalld remote approve " + orUnknown(clean(fields["provider"], 30), "ID") + ". If not, remove it now and look at what else was installed with it."
		}
	case "integration":
		t.What = "Heimdall could not use one of the things it works with (" + orUnknown(clean(fields["error_code"], 40), "a component") + ")."
		t.Do = orUnknown(clean(fields["remedy"], 200), "See Heimdall's log (journalctl -u heimdall).")
	default:
		t.What = "Heimdall noticed something (" + clean(detector, 40) + ")."
		t.Do = settings
	}
	return t
}

func orUnknown(s, fallback string) string {
	if strings.TrimSpace(strings.Trim(s, "“”")) == "" {
		return fallback
	}
	return s
}

func orEmpty(s, prefix string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

func originText(f map[string]string) string {
	if o := clean(f["origin"], 60); o != "" {
		return " (" + o + ")"
	}
	return ""
}

func srcText(f map[string]string) string {
	if s := clean(f["src"], 60); s != "" {
		return " from " + s + originText(f)
	}
	return ""
}

func versionText(f map[string]string) string {
	inst, fixed := clean(f["installed"], 40), clean(f["fixed"], 40)
	switch {
	case inst != "" && fixed != "":
		return " (installed " + inst + ", fixed in " + fixed + ")"
	case inst != "":
		return " (installed " + inst + ", no fix yet)"
	}
	return ""
}

func runningText(f map[string]string) string {
	switch f["running"] {
	case "true", "yes", "1":
		return ", including the one running now"
	case "false", "no", "0":
		return " (not the one running now)"
	}
	return ""
}
