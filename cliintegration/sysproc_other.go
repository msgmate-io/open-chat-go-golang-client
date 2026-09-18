//go:build !linux

package cliintegration

import "os/exec"

func configureSysProcAttr(cmd *exec.Cmd) {}
