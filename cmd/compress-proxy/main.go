package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/flynn/noise"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/client"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/server"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 1 && args[0] == "keygen" {
		k, e := noise.DH25519.GenerateKeypair(rand.Reader)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		if e = json.NewEncoder(os.Stdout).Encode(map[string]string{"private_key": base64.StdEncoding.EncodeToString(k.Private), "public_key": base64.StdEncoding.EncodeToString(k.Public)}); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		return 0
	}
	if len(args) == 0 || (args[0] != "check" && args[0] != "server" && args[0] != "client") {
		fmt.Fprintln(os.Stderr, "usage: compress-proxy server|client|check -c FILE | keygen")
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("c", "", "configuration file")
	if e := fs.Parse(args[1:]); e != nil || *file == "" || fs.NArg() != 0 {
		return 2
	}
	cfg, e := config.Load(*file)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	if args[0] == "check" {
		if _, e = fmt.Fprintln(os.Stdout, "configuration valid"); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		return 0
	}
	if args[0] == "server" && cfg.Server == nil || args[0] == "client" && cfg.Client == nil {
		fmt.Fprintln(os.Stderr, "configuration role does not match command")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if args[0] == "server" {
		e = server.Run(ctx, cfg.Server)
	} else {
		e = client.Run(ctx, cfg.Client)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
