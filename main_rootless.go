//go:build rootless

package main

import (
	"context"

	"ubo/contrib/rootless"
	"ubo/internal/config"
)

func init() {
	requireRootForUnlock = false
	doUnlock = func(ctx context.Context, cfg *config.Config, outDir string, changeKey bool) error {
		return rootless.Unlock(ctx, cfg, outDir, changeKey)
	}
	origCheck := checkTools
	checkTools = func(sub string) error {
		if sub == "unlock" {
			return nil
		}
		return origCheck(sub)
	}
}
