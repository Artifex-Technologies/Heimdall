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

	"github.com/Artifex-Technologies/Heimdall/internal/attack"
)

// Text is the plain-language explanation of one alert.
type Text struct {
	What    string `json:"what"`
	Serious string `json:"serious"`
	Done    string `json:"done"`
	Do      string `json:"do"`
	// Attack names the ATT&CK techniques the alert's detector watches for (the alert's "attack" IDs with their names, from
	// internal/attack): what the detector looks for, never a claim that a technique is covered. Additive; omitted when none.
	Attack []attack.Ref `json:"attack,omitempty"`
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

// For returns the explanation of an alert from its detector, event kind, severity and fields. Every detector has one; an unknown
// detector gets a general one, so a newer Heimdall never shows an alert with no words at all. The kind matters where one detector
// reports different things (lan-watch); elsewhere the detector and fields decide.
func For(detector, kind, severity string, fields map[string]string) Text {
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
	case "agent-watermark":
		t.What = "An AI agent wrote a file" + orEmpty(quoted(fields, "path"), ", ") + ", with marks a reader does not see: invisible characters, letters from another alphabet that look like ours, or spaces and tabs that spell something. They can carry instructions for another AI, mark a file so it can be traced, or make a name look like another. " + aiAgentNote
		t.Done = "Heimdall noted it; the file was not changed."
		t.Do = "Before using the file, let Sarina's stego_inspect show and clean the marks (it writes a cleaned copy beside it), or delete it. If you did not expect the agent to write it, look at the session that did."
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
		if cve := clean(fields["cve"], 40); cve != "" {
			t.What += " It is open to a known hole, " + cve + "."
		}
		if f := clean(fields["fix"], 160); f != "" {
			t.Do = "To fix it: " + f + "."
		} else {
			t.Do = "Settings > Security shows the setting and how to restore it."
		}
	case "wifi-safety":
		t.What = "A check of the Wi-Fi network " + orUnknown(quoted(fields, "ssid"), "you joined") + " found something that can expose your traffic (an open network, a weak lock, or a network pretending to be another)."
		t.Do = "Avoid signing in to anything important on this network, or turn on a VPN first."
		if fields["verdict"] == "protected" {
			t.What = "A check of the Wi-Fi network " + orUnknown(quoted(fields, "ssid"), "you joined") + " found that other devices there can see this computer, and that the protections in force cover it: it does not announce itself, its firewall turns their connections away (it answers pings, as ufw does by default) and it uses its own hardware address there."
			t.Do = "Nothing to do. The network itself can still see which sites you visit and how much you send; a VPN (heimdall-wifi-guard vpn-import) hides both."
		}
	case "lan-watch":
		lanWatch(&t, kind, fields)
	case "baseline-drift":
		t.What = "The computer behaved unlike its usual self (far more activity of some kind than normal for this time)."
		t.Do = "If you are doing something unusual (a big download, a build), nothing to do. Otherwise look at what is running."
	case "limbo-guest":
		if kind == "wine.start" {
			t.What = "A Windows program started through limbo wine" + orEmpty(quoted(fields, "program"), ": ") + ". Its content is a file Heimdall's immunity store holds (or you kept as a suspect): the same bytes are on this computer again, and Wine is no security boundary."
			t.Done = "Nothing was stopped: limbo wine runs as you, in its own sandbox, and is not a Limbo guest Heimdall can cut off."
			t.Do = "Stop the program (close it, or end the run in Limbo), find where that copy came from and delete it. The held sample's page in Settings > Security says what is known about it."
			break
		}
		t.What = "A program running in a Limbo sandbox broke the sandbox's safety rules" + orEmpty(quoted(fields, "guest"), ": ") + "."
		t.Done = "Heimdall asked Limbo to cut the sandbox off (quarantine). Limbo never lets Heimdall release it; only you can."
		t.Do = "Look at the quarantine in Settings > Security before releasing anything; if unsure, delete the sandbox."
	case "limbo-network":
		guest := orUnknown(quoted(fields, "guest"), "a sandbox")
		if kind == "sinkhole.dns" || kind == "sinkhole.connect" {
			t.What = "A program in the Limbo sandbox " + guest + " tried to reach the internet. The sandbox has no route out: Limbo's sinkhole answered it and wrote down what it tried. A sample that does this is calling home, as malware does to report in or fetch more."
			t.Done = "Nothing left this computer. Limbo kept what the program tried (names, addresses, the first bytes) in its log and the run's result."
			t.Do = "Treat the file as hostile unless you know why it would reach out (an installer looking for updates does). The held file's analysis lists everything it tried."
			break
		}
		switch fields["reason"] {
		case "host_probe":
			t.What = "A program in the Limbo sandbox " + guest + " tried to reach this computer itself. Its firewall refused it, but a sandboxed program has no reason to knock on its host."
		case "lan_probe":
			t.What = "A program in the Limbo sandbox " + guest + " tried to reach your home network, the router or another sandbox. Its firewall refused it."
		case "scan":
			t.What = "A program in the Limbo sandbox " + guest + " tried many different addresses in a short time and was refused each time. That is what a scan looks like."
		case "ipv6":
			t.What = "A program in the Limbo sandbox " + guest + " tried to send IPv6 traffic out. Sandboxes have no IPv6, so it went nowhere."
		case "":
			t.What = "The Limbo sandbox " + guest + " used up its budget of recorded network destinations. Limbo keeps reporting anything that looks like probing."
		default:
			t.What = "Limbo reported unusual refused network traffic from the sandbox " + guest + "."
		}
		switch fields["reason"] {
		case "host_probe", "lan_probe", "scan":
			t.Done = "Nothing got through: the sandbox's firewall refused it. If automatic restriction is on in Heimdall's settings, Heimdall also asked Limbo to cut the sandbox's network (quarantine); only you can release it."
			t.Do = "Look at what runs in the sandbox (Settings > Security shows any quarantine). If you do not know why it would do this, delete the sandbox."
		case "":
			t.Done = "Nothing was changed; Limbo only stops writing down new ordinary destinations for this sandbox."
			t.Do = "Nothing, unless other alerts name the same sandbox."
		default:
			t.Done = "Nothing got through: the sandbox's firewall refused it."
			t.Do = "If other alerts name the same sandbox, read them together; otherwise nothing to do."
		}
	case "limbo-exchange":
		guest := orUnknown(quoted(fields, "guest"), "a sandbox")
		if fields["signature"] != "" || severity != "info" {
			t.What = "A program in the Limbo sandbox " + guest + " tried to hand you a file (" + orUnknown(quoted(fields, "guest_path"), "unnamed") + ") that ClamAV knows as malware (" + orUnknown(clean(fields["signature"], 80), "a known signature") + ")."
			t.Done = "Limbo kept the file back, where only root can read it; it did not reach you."
			t.Do = "Do not copy files out of this sandbox by other means. The sandbox itself is probably infected: if you do not need it, delete it. To keep a copy in Heimdall's own malware store (root-only, never run): sudo heimdalld immunity take-limbo " + sha256OrPlaceholder(fields["sha256"]) + "."
		} else {
			t.What = "A file in the Limbo sandbox " + guest + "'s outbox (" + orUnknown(quoted(fields, "guest_path"), "unnamed") + ") could not be scanned, so Limbo did not hand it out."
			t.Done = "The file stayed inside the sandbox."
			t.Do = "Check that ClamAV is running (systemctl status clamav-daemon), then try again."
		}
	case "tool-rules":
		prog := orUnknown(quoted(fields, "script"), orUnknown(quoted(fields, "exe"), "a security tool's program"))
		t.What = "The program file of a security tool (" + prog + ") is not the one its package installed. Heimdall lets a verified tool scan and connect quietly on a security system; a changed one could be malware using the tool's name."
		t.Do = "Find out what changed the file (pacman -Qkk, the package's last update, what you ran), then reinstall the package. Until then, do not use the tool."
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
	case "agent-baseline":
		t.What = "The AI agent behaved unlike its usual self: far more sessions or tool calls than normal for it, or a tool it had never used. " + aiAgentNote
		t.Do = "If you just gave it a big job (or the evals are running), nothing to do. Otherwise look at its latest sessions and at any other alert about them."
	case "rule-draft":
		t.What = "A rule that recognises a held malware sample and its variants was drafted (" + orUnknown(clean(fields["rule"], 70), "a YARA rule") + "). It does nothing until you approve it."
		t.Do = "Test it (it must match the sample and none of this computer's programs), read it, then approve or reject it: sudo heimdalld immunity rule test " + orUnknown(clean(fields["rule_id"], 20), "ID") + "."
	case "incident":
		t.What = "Several of Heimdall's alerts are about the same thing (" + orUnknown(clean(fields["keys"], 160), "a session, address or program") + ") within a short time: " + orUnknown(clean(fields["detectors"], 120), "several checks") + ". Each alone may be harmless; together they tell one story."
		t.Do = "Read these alerts together, oldest first (Settings > Security, or heimdalld's API /v1/incidents). Act on the most serious one."
	case "grant-request":
		t.What = "An AI agent asks for more than it has: " + orUnknown(clean(fields["kind"], 20), "a grant") + " " + orUnknown(clean(fields["detail"], 40), "") + ". It cannot give this to itself; only you can."
		t.Done = "Heimdall recorded the request. Nothing changes until you decide."
		t.Do = "If you asked the agent to do something that needs it, allow it: sudo heimdalld grant approve " + orUnknown(clean(fields["request_id"], 20), "ID") + ". If not, deny it: sudo heimdalld grant deny " + orUnknown(clean(fields["request_id"], 20), "ID") + "."
	case "integration":
		t.What = "Heimdall could not use one of the things it works with (" + orUnknown(clean(fields["error_code"], 40), "a component") + ")."
		t.Do = orUnknown(clean(fields["remedy"], 200), "See Heimdall's log (journalctl -u heimdall).")
	default:
		t.What = "Heimdall noticed something (" + clean(detector, 40) + ")."
		t.Do = settings
	}
	return t
}

// lanWatch explains a lan-watch alert by its event kind: each thing the local-network watch reports gets its own words (what
// happened, why it matters, what to do). An unknown kind, from a newer source, gets general words, never a wrong story.
func lanWatch(t *Text, kind string, fields map[string]string) {
	network := orUnknown(quoted(fields, "ssid"), "this network")
	switch kind {
	case "router_changed":
		t.What = "While you were connected to " + network + ", the router's hardware address changed (to " + orUnknown(clean(fields["new_mac"], 40), "a new one") + "). A router keeps its hardware address; when another device starts answering in its place, everything you send goes through that device, which can read or change it (ARP spoofing)."
		t.Do = "Disconnect, or turn on a VPN before doing anything private. On a network of your own, a router you just replaced does this too."
	case "router_impersonated":
		t.What = "On " + network + ", another device (" + orUnknown(clean(fields["other_ip"], 60), "an unknown address") + ") answers with the router's hardware address. A device claiming to be the router gets the traffic meant for it, and can read or change it (ARP spoofing)."
		t.Do = "Disconnect, or turn on a VPN before doing anything private. At home, restart the router and look for that address in Settings > Wi-Fi & Network > Devices."
	case "rogue_router":
		what := orUnknown(clean(fields["what"], 300), "a DHCP server or IPv6 router other than the known one")
		if fields["judged"] == "info" {
			t.What = "One thing about the router of " + network + " changed since last time: " + what + ". A firmware update or a new setting on the router does this."
			t.Do = "Nothing to do. Heimdall warns if more about the router changes at once."
			break
		}
		t.What = "A second router may be on " + network + ": " + what + ". A device that hands out addresses or announces itself as the router can put itself between this computer and the internet (man in the middle)."
		if fields["learned"] == "true" {
			t.What += " It does not match the router remembered for this network."
		}
		t.Done = "Heimdall noted it; nothing was blocked, so everyone on the network can still use it."
		t.Do = "On a network you do not control, disconnect or use a VPN. At home, if you did not add or replace a router, look for a device you do not know (Settings > Wi-Fi & Network > Devices)."
	case "lan_device_changed":
		if change := fields["change"]; change == "name_moved" || change == "name_shared" {
			name := orUnknown(quoted(fields, "was_name"), "a known device's name")
			newer := orUnknown(clean(fields["mac"], 40), "a different hardware address")
			if change == "name_shared" {
				t.What = "On " + network + ", a device you know answers to " + name + ", and now another one (" + newer + ") announces the same name. Two devices left with one default name do this; so does a device posing as another, so that what is meant for it (print jobs, casts, sign-ins) comes to it instead."
			} else {
				t.What = "On " + network + ", " + name + " is now announced by another hardware address (" + newer + "), and the one that had it is not seen. A phone, tablet or laptop that changed its private address does this (both addresses are then private), and so does a replaced device; a device posing as another while it is away does too."
			}
			t.Done = "Heimdall noted it; nothing was blocked."
			t.Do = "Look at both devices in Settings > Wi-Fi & Network > Devices. If you did not replace the device and do not know the new one, rename the device you know, restart the router and change the Wi-Fi password."
			break
		}
		was := orUnknown(quoted(fields, "was_name"), orUnknown(clean(fields["was_mac"], 40), "a device you know"))
		other := orUnknown(clean(fields["other_ip"], 60), "its own address")
		t.What = "On " + network + ", the address " + orUnknown(clean(fields["ip"], 60), "of a known device") + " belonged to " + was + "; now another device (" + orUnknown(clean(fields["mac"], 40), "a different hardware address") + ") answers for it, and also for " + other + ". One device answering for another is how someone puts itself between the devices of a network and reads what they send (ARP spoofing)."
		t.Done = "Heimdall noted it; nothing was blocked."
		t.Do = "Look at both devices in Settings > Wi-Fi & Network > Devices. If you do not know the one at " + other + ", restart the router and change the Wi-Fi password."
	case "new_lan_device":
		who := orUnknown(quoted(fields, "name"), "A device")
		about := ""
		if v := quoted(fields, "vendor"); v != "" {
			about = ", made by " + v
		} else if fields["private_mac"] == "true" {
			about = ", using a private hardware address (phones, tablets and laptops usually do, so its maker is not known)"
		}
		t.What = who + about + " joined " + network + " for the first time, at " + orUnknown(clean(fields["ip"], 60), "an unknown address") + ". Heimdall tells you about every new device on your home network, so nobody joins it unnoticed."
		t.Do = "If it is yours or a guest's (a new phone, a TV, a visitor), nothing to do. If you do not know it, look at it in Settings > Wi-Fi & Network > Devices; a device you cannot place is a reason to change the Wi-Fi password."
	case "new_listener":
		port := digitsOr(fields["port"], "PORT")
		shown := "port " + port
		if port == "PORT" {
			shown = "port unknown"
		}
		t.What = "A program on this computer started listening for connections from the network (" + orUnknown(clean(fields["proto"], 10), "a protocol") + ", " + shown + "). Programs that share something (a game server, file sharing, a remote desktop) do this; so does malware waiting for orders."
		t.Done = "Heimdall noted it. The firewall still turns connections to it away unless a rule allows that port."
		t.Do = "If you just started something that shares over the network, nothing to do. Otherwise find the program (sudo ss -tulpn | grep ':" + port + " ') and stop it."
	case "wifi_inbound":
		src := orUnknown(clean(fields["src"], 60), "an unknown address")
		if fields["router"] == "true" {
			t.What = "The router of this Wi-Fi network (" + src + ") reached for this computer. Routers that keep a list of their devices look at each one now and then."
			t.Done = "Heimdall noted it, once per connection."
			t.Do = "Nothing to do."
			break
		}
		t.What = "A device on the Wi-Fi network (" + src + ") tried to reach this computer directly: a connection, a ping or a question about it."
		t.Done = "Heimdall noted it. The firewall drops what it does not allow (it answers pings, as ufw does by default), so nothing got in unless a rule allows that port."
		t.Do = "Usually nothing. If it keeps happening, find out which device it is (Settings > Wi-Fi & Network); on a network you do not control, a VPN also hides your traffic."
	default:
		t.What = "Heimdall's watch of the local network noticed a change in the devices on it or in its router."
		t.Do = "Settings > Wi-Fi & Network > Devices shows who is on the network. On a network you do not control, a VPN keeps your traffic private."
	}
}

// digitsOr puts a port into a suggested command only when it is one (1 to 5 digits); anything else becomes the placeholder.
func digitsOr(s, placeholder string) string {
	if len(s) == 0 || len(s) > 5 || strings.Trim(s, "0123456789") != "" {
		return placeholder
	}
	return s
}

// sha256OrPlaceholder puts a SHA-256 into a suggested command only when it is one (64 hex characters); anything else
// becomes the word SHA256, so no observed text ever lands in a command line.
func sha256OrPlaceholder(s string) string {
	if len(s) != 64 || strings.Trim(strings.ToLower(s), "0123456789abcdef") != "" {
		return "SHA256"
	}
	return s
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
