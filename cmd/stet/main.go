package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	ctx := context.Background()
	cmd := newRootCmd()
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
