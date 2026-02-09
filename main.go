package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/api"
	_ "github.com/c137req/ptv/internal/formats"
	"github.com/c137req/ptv/internal/module"
)

var _verbose bool

func _log(msg string, args ...any) {
	if _verbose {
		fmt.Fprintf(os.Stderr, "[ptv] "+msg+"\n", args...)
	}
}

func main() {
	from := flag.String("from", "", "source format name")
	to := flag.String("to", "", "target format name")
	input := flag.String("i", "-", "input file (- for stdin)")
	output := flag.String("o", "-", "output file (- for stdout)")
	verbose := flag.Bool("v", false, "verbose output to stderr")
	list_fmts := flag.Bool("formats", false, "list available formats")

	// daemon / api flags
	daemon := flag.String("daemon", "", "daemon control: start, stop, status")
	bind := flag.String("bind", "0.0.0.0:0474", "api bind address")
	random_port := flag.Bool("random-port", false, "pick a random available port")
	api_key := flag.String("api-key", "", "api key (or PTV_API_KEY env; auto-generated if empty)")
	max_body := flag.Int64("max-body", 10<<20, "maximum request body bytes")
	rate_rpm := flag.Int("rate-limit", 60, "requests per minute per ip")
	cors := flag.String("cors-origin", "", "allowed CORS origin")
	tls_cert := flag.String("tls-cert", "", "tls certificate path")
	tls_key := flag.String("tls-key", "", "tls private key path")
	pid_file := flag.String("pid-file", "/tmp/ptv.pid", "daemon pid file path")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout")

	flag.Parse()
	_verbose = *verbose

	// daemon mode
	if *daemon != "" {
		// resolve api key: flag > env > auto-generate
		key := *api_key
		if key == "" {
			key = os.Getenv("PTV_API_KEY")
		}
		if key == "" && *daemon == "start" {
			generated, err := api.GenerateKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to generate api key: %v\n", err)
				os.Exit(1)
			}
			key = generated
			fmt.Fprintf(os.Stderr, "[ptv] generated api key: %s\n", key)
		}

		// handle random port
		addr := *bind
		if *random_port {
			// replace port with 0 for OS assignment
			parts := strings.Split(addr, ":")
			if len(parts) >= 2 {
				parts[len(parts)-1] = "0"
				addr = strings.Join(parts, ":")
			} else {
				addr = addr + ":0"
			}
		}

		switch *daemon {
		case "start":
			srv := api.NewServer(addr, key, *max_body, *rate_rpm, *cors,
				*tls_cert, *tls_key, *timeout, _verbose, _log)
			if err := api.DaemonStart(srv, *pid_file); err != nil {
				fmt.Fprintf(os.Stderr, "daemon start failed: %v\n", err)
				os.Exit(1)
			}
		case "stop":
			if err := api.DaemonStop(*pid_file, _log); err != nil {
				fmt.Fprintf(os.Stderr, "daemon stop failed: %v\n", err)
				os.Exit(1)
			}
		case "status":
			api.DaemonStatus(*pid_file, _log)
		default:
			fmt.Fprintf(os.Stderr, "unknown daemon command: %s (use start, stop, or status)\n", *daemon)
			os.Exit(1)
		}
		return
	}

	if *list_fmts {
		fmts := module.List()
		fmt.Printf("%d formats available:\n", len(fmts))
		for _, f := range fmts {
			fmt.Printf("  %s\n", f)
		}
		return
	}

	if *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: ptv -from <format> -to <format> [-i input] [-o output] [-v]")
		fmt.Fprintln(os.Stderr, "       ptv -formats")
		fmt.Fprintln(os.Stderr, "       ptv -daemon <start|stop|status> [-bind addr] [-api-key key] [-v]")
		os.Exit(1)
	}

	from_mod, ok := module.Get(*from)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown source format: %s\n", *from)
		fmt.Fprintf(os.Stderr, "available: %s\n", strings.Join(module.List(), ", "))
		os.Exit(1)
	}

	to_mod, ok := module.Get(*to)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown target format: %s\n", *to)
		fmt.Fprintf(os.Stderr, "available: %s\n", strings.Join(module.List(), ", "))
		os.Exit(1)
	}

	raw, err := _read_input(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %v\n", err)
		os.Exit(1)
	}
	_log("read %d bytes from %s", len(raw), *input)

	_log("parsing with %s module", *from)
	ds, err := from_mod.Parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error (%s): %v\n", *from, err)
		os.Exit(1)
	}
	_log("parsed %d records", ds.Meta.RecordCount)

	_log("rendering with %s module", *to)
	out, err := to_mod.Render(ds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render error (%s): %v\n", *to, err)
		os.Exit(1)
	}
	_log("rendered %d bytes", len(out))

	if err := _write_output(*output, out); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
		os.Exit(1)
	}
}

func _read_input(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func _write_output(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}
