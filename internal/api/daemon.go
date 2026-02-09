package api

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DaemonStart starts the server and blocks until signal or error.
// writes PID file, handles graceful shutdown on SIGTERM/SIGINT.
func DaemonStart(s *_server, pid_path string) error {
	if pid, err := _read_pid(pid_path); err == nil {
		if _process_alive(pid) {
			return fmt.Errorf("daemon already running (pid %d)", pid)
		}
		os.Remove(pid_path)
	}

	if err := s.Listen(); err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.bind, err)
	}

	if err := _write_pid(pid_path); err != nil {
		return fmt.Errorf("failed to write pid file: %w", err)
	}
	defer os.Remove(pid_path)

	s.cfg.log_fn("listening on %s", s.Addr())

	err_ch := make(chan error, 1)
	go func() {
		err_ch <- s.Serve()
	}()

	sig_ch := make(chan os.Signal, 1)
	signal.Notify(sig_ch, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sig_ch:
		s.cfg.log_fn("received %s, shutting down", sig)
	case err := <-err_ch:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}

	return s.Shutdown(30 * time.Second)
}

// DaemonStop sends SIGTERM to the running daemon and waits for exit.
func DaemonStop(pid_path string, log_fn func(string, ...any)) error {
	pid, err := _read_pid(pid_path)
	if err != nil {
		return fmt.Errorf("no pid file at %s: not running?", pid_path)
	}

	if !_process_alive(pid) {
		os.Remove(pid_path)
		return fmt.Errorf("stale pid file (pid %d not running), removed", pid)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("cannot find process %d: %w", pid, err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to %d: %w", pid, err)
	}

	log_fn("sent SIGTERM to pid %d", pid)

	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if !_process_alive(pid) {
			os.Remove(pid_path)
			log_fn("daemon stopped")
			return nil
		}
	}

	return fmt.Errorf("daemon (pid %d) did not exit within 30 seconds", pid)
}

// DaemonStatus checks whether the daemon is running.
func DaemonStatus(pid_path string, log_fn func(string, ...any)) {
	pid, err := _read_pid(pid_path)
	if err != nil {
		log_fn("not running (no pid file)")
		return
	}

	if _process_alive(pid) {
		log_fn("running (pid %d)", pid)
	} else {
		log_fn("not running (stale pid file for pid %d)", pid)
		os.Remove(pid_path)
	}
}

func _write_pid(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func _read_pid(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func _process_alive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
