package module

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"sync"

	"github.com/c137req/ptv/internal/ir"
)

type Module interface {
	Name() string
	Parse(raw []byte) (*ir.Dataset, error)
	Render(ds *ir.Dataset) ([]byte, error)
}

var (
	_registry = map[string]Module{}
	_mu       sync.RWMutex
)

func Register(m Module) {
	_mu.Lock()
	_registry[m.Name()] = m
	_mu.Unlock()
}

func Get(name string) (Module, bool) {
	_mu.RLock()
	m, ok := _registry[name]
	_mu.RUnlock()
	return m, ok
}

func List() []string {
	_mu.RLock()
	names := make([]string, 0, len(_registry))
	for k := range _registry {
		names = append(names, k)
	}
	_mu.RUnlock()
	sort.Strings(names)
	return names
}

// PyModule wraps a python script as a Module.
// the script reads json from stdin and writes json to stdout.
type PyModule struct {
	ModName    string
	ScriptPath string
}

func (m *PyModule) Name() string { return m.ModName }

func (m *PyModule) Parse(raw []byte) (*ir.Dataset, error) {
	req := map[string]string{"direction": "from", "data": string(raw)}
	out, err := _py_call(m.ScriptPath, req)
	if err != nil {
		return nil, err
	}
	var ds ir.Dataset
	if err := json.Unmarshal(out, &ds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal python output: %w", err)
	}
	return &ds, nil
}

func (m *PyModule) Render(ds *ir.Dataset) ([]byte, error) {
	req := map[string]any{"direction": "to", "data": ds}
	out, err := _py_call(m.ScriptPath, req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal python output: %w", err)
	}
	return []byte(resp.Output), nil
}

func _py_call(script string, req any) ([]byte, error) {
	input, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("python3", script)
	cmd.Stdin = nil
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		stdin.Write(input)
		stdin.Close()
	}()
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("python module error: %s", string(exitErr.Stderr))
		}
		return nil, err
	}
	return out, nil
}
