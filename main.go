package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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

	flag.Parse()
	_verbose = *verbose

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
