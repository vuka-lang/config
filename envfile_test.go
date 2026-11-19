package config

import (
	"math/rand"
	"strings"
	"testing"
)

// The cases of web's TestParseDotEnv: the two parsers read one syntax.
func TestParseEnv(t *testing.T) {
	env := map[string]string{"HOME": "/home/me", "EMPTY": ""}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	for _, c := range []struct{ name, src, want, err string }{
		{"plain", "A=1\nB=two words", "A=1|B=two words", ""},
		{"export", "export A=1\nexport\tB=2", "A=1|B=2", ""},
		{"comments and blanks", "# top\n\n  # indented\nA=1 # note\nB=x#y\nC= #only\nD=#also", "A=1|B=x#y|C=|D=", ""},
		{"spacing", "  A  =   hello world  \t\nB=", "A=hello world|B=", ""},
		{"crlf and bom", "\xef\xbb\xbfA=1\r\nB='2'\r\n", "A=1|B=2", ""},
		{"single quotes are literal", `A='$HOME \n ${X} # no'`, `A=$HOME \n ${X} # no`, ""},
		{"backticks are literal", "A=`it's \"$HOME\"`", `A=it's "$HOME"`, ""},
		{"double quote escapes", `A="a\nb\tc\"q\" \\ \$HOME \z" # c`, "A=a\nb\tc\"q\" \\ $HOME \\z", ""},
		{"multi-line", "A=\"one\ntwo\"\nB='three\nfour'\nC=5", "A=one\ntwo|B=three\nfour|C=5", ""},
		{"dotted keys", "a.b=1\nC=${a.b}", "a.b=1|C=1", ""},
		{"expansion", "A=x\nB=${A}y\nC=$A.z\nD=\"$HOME/${A}\"\nE='$A'", "A=x|B=xy|C=x.z|D=/home/me/x|E=$A", ""},
		{"defaults", "A=x\nB=${NOPE:-d}\nC=${A:-d}\nD=${EMPTY:-d}\nE=${NOPE:-${A}-2}\nF=\"${NOPE:-a b}\"", "A=x|B=d|C=x|D=d|E=x-2|F=a b", ""},
		{"undefined is empty", "A=[$NOPE][${NOPE}]", "A=[][]", ""},
		{"no cycles: only keys defined above", "A=${B}\nB=${A}", "A=|B=", ""},
		{"later wins, self reference", "A=1\nA=${A}2\nB=$A", "A=1|A=12|B=12", ""},
		{"the process wins", "HOME=/x\nB=$HOME", "HOME=/x|B=/home/me", ""},
		{"a lone dollar", "A=$ 5 $1 $", "A=$ 5 $1 $", ""},
		{"no key", "A=1\n=2", "", "f.env:2: expected KEY=value"},
		{"bad key", "1A=x", "", "f.env:1: expected KEY=value"},
		{"no equals", "A=1\n\nexport B", "", "f.env:3: expected KEY=value"},
		{"unterminated single", "A=1\nB='x\ny", "", "f.env:2: unterminated '-quoted value of B"},
		{"unterminated double", `A="x`, "", "f.env:1: unterminated double-quoted value of A"},
		{"text after quote", `A="x" y`, "", "f.env:1: unexpected text after the closing quote"},
		{"line after a multi-line value", "A=\"1\n2\"\nB='3\n4'\nnope", "", "f.env:5: expected KEY=value"},
		{"unterminated brace", "A=${B", "", "f.env:1: unterminated ${"},
		{"bad reference", "A=${1B}", "", "f.env:1: bad variable reference ${1B}"},
	} {
		pairs, err := ParseEnv("f.env", []byte(c.src), lookup, nil)
		if c.err != "" {
			if err == nil || err.Error() != c.err {
				t.Errorf("%s: err %v; want %q", c.name, err, c.err)
			}
			continue
		}
		var got []string
		for _, p := range pairs {
			got = append(got, p.Key+"="+p.Value)
		}
		if err != nil || strings.Join(got, "|") != c.want {
			t.Errorf("%s: %q, %v; want %q", c.name, strings.Join(got, "|"), err, c.want)
		}
	}
}

func TestParseEnvLowerLayers(t *testing.T) {
	pairs, err := ParseEnv("f.env", []byte("B=${A}-b\nC=${NOPE:-d}"), nil, map[string]string{"A": "low"})
	if err != nil || len(pairs) != 2 || pairs[0].Value != "low-b" || pairs[1].Value != "d" {
		t.Errorf("%v %v", pairs, err)
	}
}

func TestFormatEnvRoundTrips(t *testing.T) {
	in := map[string]string{
		"PLAIN": "x", "EMPTY": "", "DOLLAR": "$HOME ${X} $", "QUOTES": `a"b'c` + "`d",
		"LINES": "one\ntwo\r\n\tthree", "SLASH": `C:\path\n`, "HASH": "a # b #c", "a.dotted": "v",
		"SPACES": "  padded  ", "UNI": "héllo ✓",
	}
	rnd := rand.New(rand.NewSource(1))
	const alphabet = "ab $\\\"'`#\n\t\r{}:-="
	for i := 0; i < 200; i++ {
		b := make([]byte, rnd.Intn(12))
		for j := range b {
			b[j] = alphabet[rnd.Intn(len(alphabet))]
		}
		in["R"+string(rune('A'+i%26))+strings.Repeat("_", i/26)] = string(b)
	}
	out := FormatEnv(in)
	pairs, err := ParseEnv("out.env", out, nil, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := map[string]string{}
	for _, p := range pairs {
		got[p.Key] = p.Value
	}
	if len(got) != len(in) {
		t.Fatalf("%d keys back, want %d", len(got), len(in))
	}
	for k, v := range in {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if string(FormatEnv(map[string]string{"B": "2", "A": "1"})) != "A=\"1\"\nB=\"2\"\n" {
		t.Error("keys are not sorted")
	}
}
