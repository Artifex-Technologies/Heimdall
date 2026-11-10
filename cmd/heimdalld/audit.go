package main

import (
	"github.com/Artifex-Technologies/Heimdall/internal/auditreport"
	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/hardening"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
)

// audit is what GET /v1/audit answers: everything open now (internal/auditreport).
func audit(cfg config.Config) any {
	return auditreport.Build(auditreport.Computer{Tracker: cfg.SecurityTracker, PacmanDB: cfg.PacmanDB, KernelVulns: cfg.KernelVulns,
		Modules: "/usr/lib/modules", Running: kernelaudit.Running(), System: hardening.System{}})
}
