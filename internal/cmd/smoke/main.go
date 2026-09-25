package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	binary := flag.String("binary", "./bin/compress-proxy", "compiled binary")
	mode := flag.String("transport", "both", "noise, wss, or both")
	flag.Parse()
	if *mode != "both" && *mode != "noise" && *mode != "wss" {
		fmt.Fprintln(os.Stderr, "invalid transport")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fmt.Println("smoke_started")
	modes := []string{*mode}
	if *mode == "both" {
		modes = []string{"noise", "wss"}
	}
	for _, kind := range modes {
		if e := scenarios(ctx, *binary, kind); e != nil {
			fmt.Fprintln(os.Stderr, "FAIL", kind, e)
			os.Exit(1)
		}
	}
}
func pass(kind, scenario string) { fmt.Println("PASS", kind, scenario) }
