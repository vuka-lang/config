package client_test

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vuka-lang/web/v2"
)

func TestRestartOnlyKeyIsReportedByKey(t *testing.T) {
	logs := captureLog(t)
	web.RestartOnlyEnv("RK1_DB")
	l := newLive(t, map[string]string{"orders/.env.production": "RK1_DB=db-one-secretish\nRK1_LIVE=live-one-secretish\n"})
	open(t, l.config(t))

	l.write("orders/.env.production", "RK1_DB=db-two-secretish\nRK1_LIVE=live-two-secretish\n")
	eventually(t, "the new values", is(env("RK1_DB"), "db-two-secretish"))
	eventually(t, "the restart line", func() bool { return strings.Contains(logs.String(), "take effect on restart") })

	var applied, restart string
	for _, line := range strings.Split(logs.String(), "\n") {
		switch {
		case strings.Contains(line, "config: applied "):
			applied = line
		case strings.Contains(line, "take effect on restart"):
			restart = line
		}
	}
	if !strings.HasSuffix(restart, "config: RK1_DB changed and take effect on restart") {
		t.Errorf("restart line: %q", restart)
	}
	if !strings.Contains(applied, "RK1_DB, RK1_LIVE") || !strings.HasSuffix(applied, "; restart needed for RK1_DB") {
		t.Errorf("applied line: %q", applied)
	}
	if strings.Contains(logs.String(), "restarting") {
		t.Errorf("restarted without VUKA_CONFIG_RESTART:\n%s", logs.String())
	}
	noValues(t, logs, "db-one-secretish", "db-two-secretish", "live-one-secretish", "live-two-secretish")
}

func TestLiveKeyChangeLogsNormally(t *testing.T) {
	logs := captureLog(t)
	web.RestartOnlyEnv("RK2_DB")
	l := newLive(t, map[string]string{"orders/.env.production": "RK2_DB=a\nRK2_LIVE=a\n"})
	c := l.config(t)
	c.Restart = true
	open(t, c)

	l.write("orders/.env.production", "RK2_DB=a\nRK2_LIVE=b\n")
	eventually(t, "the new value", is(env("RK2_LIVE"), "b"))
	eventually(t, "the applied line", func() bool { return strings.Contains(logs.String(), "config: applied 1 change") })
	if s := logs.String(); strings.Contains(s, "restart") {
		t.Errorf("a live key was reported as needing a restart:\n%s", s)
	}
}

func TestRestartWithoutAnAppSaysSo(t *testing.T) {
	logs := captureLog(t)
	web.RestartOnlyEnv("RK3_DB")
	l := newLive(t, map[string]string{"orders/.env.production": "RK3_DB=a\n"})
	c := l.config(t)
	c.Restart = true
	open(t, c)

	l.write("orders/.env.production", "RK3_DB=b\n")
	eventually(t, "the message", func() bool { return strings.Contains(logs.String(), "no app is running to restart") })
}

// The child of TestRestartExitsWithItsStatus: an app following the server the
// parent runs through the client's own start-up, as a program that imports
// the package does; the parent gives it the address in the environment.
func TestRestartChild(t *testing.T) {
	uri := os.Getenv("RK_CHILD_URI")
	if uri == "" {
		t.Skip("run by TestRestartExitsWithItsStatus")
	}
	web.RestartOnlyEnv("RK4_DB")
	app := web.New(web.NoDotEnv(), web.OnStop(func(context.Context) error {
		log.Print("child: services stopped")
		return nil
	}))
	if err := app.Run("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
}

func TestRestartExitsWithItsStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the child is stopped with a signal")
	}
	for _, tc := range []struct {
		name, change string
		restarts     bool
	}{
		{"a restart-only key", "RK4_DB=db-two-secretish\nRK4_LIVE=a\n", true},
		{"a live key", "RK4_DB=db-one-secretish\nRK4_LIVE=b\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLive(t, map[string]string{"orders/.env.production": "RK4_DB=db-one-secretish\nRK4_LIVE=a\n"})
			cmd := exec.Command(os.Args[0], "-test.run=^TestRestartChild$")
			cmd.Env = append(os.Environ(),
				"RK_CHILD_URI="+l.srv.URL, "VUKA_CONFIG_URI="+l.srv.URL, "VUKA_CONFIG_TOKEN="+token,
				"VUKA_CONFIG_KEY="+l.pub, "VUKA_APP=orders", "VUKA_ENV=production", "VUKA_CONFIG_RESTART=1",
				"VUKA_CONFIG_CACHE="+filepath.Join(t.TempDir(), "orders.snapshot"))
			stderr, _ := cmd.StderrPipe()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := make(chan string, 100)
			go func() {
				sc := bufio.NewScanner(stderr)
				for sc.Scan() {
					lines <- sc.Text()
				}
				close(lines)
			}()
			var out strings.Builder
			wait := func(want string) {
				t.Helper()
				timeout := time.After(10 * time.Second)
				for !strings.Contains(out.String(), want) {
					select {
					case line, ok := <-lines:
						if !ok {
							t.Fatalf("the child ended before %q:\n%s", want, out.String())
						}
						out.WriteString(line + "\n")
					case <-timeout:
						cmd.Process.Kill()
						t.Fatalf("timed out waiting for %q:\n%s", want, out.String())
					}
				}
			}
			wait("web: listening")
			l.write("orders/.env.production", tc.change)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			if tc.restarts {
				wait("config: restarting to apply RK4_DB")
			} else {
				wait("config: applied 1 change")
				select {
				case err := <-done:
					t.Fatalf("the child exited on a live key's change: %v\n%s", err, out.String())
				case <-time.After(500 * time.Millisecond):
				}
				cmd.Process.Signal(syscall.SIGTERM)
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(15 * time.Second):
				cmd.Process.Kill()
				t.Fatal("the child didn't exit")
			}
			for line := range lines {
				out.WriteString(line + "\n")
			}
			status := 0
			if ee, ok := err.(*exec.ExitError); ok {
				status = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			want := 0
			if tc.restarts {
				want = web.RestartStatus
			}
			if status != want {
				t.Errorf("exit status %d, want %d:\n%s", status, want, out.String())
			}
			if !strings.Contains(out.String(), "child: services stopped") {
				t.Errorf("the services weren't stopped before the exit:\n%s", out.String())
			}
			for _, v := range []string{"db-one-secretish", "db-two-secretish", token} {
				if strings.Contains(out.String(), v) {
					t.Errorf("the child's log holds %q:\n%s", v, out.String())
				}
			}
		})
	}
}
