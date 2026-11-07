package secretclass

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Literal, inert fixtures only. These deliberately fake values are not credentials.
const (
	fakeClassic = "gh" + "p_" + "SYNTHETIC000000000000000000000000000"
	fakeOAuth   = "gh" + "o_" + "SYNTHETIC000000000000000000000000000"
	fakeUser    = "gh" + "u_" + "SYNTHETIC000000000000000000000000000"
	fakeServer  = "gh" + "s_" + "SYNTHETIC000000000000000000000000000"
	fakeRefresh = "gh" + "r_" + "SYNTHETIC000000000000000000000000000"
	fakeFine    = "git" + "hub_pat_" + "SYNTHETIC0000000000000_SYNTHETIC00000000000000000000000000000000000000000000000000"
	fakeEscaped = `"ghp_\u0053YNTHETIC000000000000000000000000000"`
)

func check(t *testing.T, input string, format Format, want Counts, wantErr error) {
	t.Helper()
	got, err := Classify([]byte(input), format)
	if !errors.Is(err, wantErr) || got != want {
		// No input, expected values or parser diagnostics may appear in test logs.
		t.Fatal("classification count/error mismatch")
	}
	if err != nil && got.Blocking() {
		t.Fatal("refusal returned partial counts")
	}
	if err == nil && got.Blocking() != (want.GitHubTokens+want.SecretFields > 0) {
		t.Fatal("blocking classification mismatch")
	}
}

func TestTokenShapes(t *testing.T) {
	if len(fakeClassic) != 4+36 || len(fakeFine) != 11+82 {
		t.Fatal("synthetic boundary fixture length mismatch")
	}
	for _, input := range []string{fakeClassic, fakeOAuth, fakeUser, fakeServer, fakeRefresh, fakeFine} {
		check(t, input, Auto, Counts{GitHubTokens: 1}, nil)
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal("synthetic fixture encoding failed")
		}
		check(t, string(encoded), JSON, Counts{GitHubTokens: 1}, nil)
		check(t, "embedded"+input+"overflow", Auto, Counts{GitHubTokens: 1}, nil)
	}
	check(t, fakeClassic+"\n"+fakeFine, Auto, Counts{GitHubTokens: 2}, nil)
	check(t, fakeClassic[:len(fakeClassic)-1], Auto, Counts{}, nil)
	check(t, fakeFine[:len(fakeFine)-1], Auto, Counts{}, nil)
	check(t, "ghx_SYNTHETIC000000000000000000000000000", Auto, Counts{}, nil)
	check(t, strings.ToUpper(fakeClassic), Auto, Counts{}, nil)
	check(t, fakeEscaped, JSON, Counts{GitHubTokens: 1}, nil)
	check(t, `"ghp_\u0053YNTHETIC00000000000000000000000000!"`, JSON, Counts{}, nil)
	check(t, "ordinary SYNTHETIC inert text", Auto, Counts{}, nil)
}

func TestSecretFieldsEmptyAndNonempty(t *testing.T) {
	for _, value := range []string{`null`, `""`, `[]`, `{}`} {
		for _, key := range []string{"temp_clone_token", "token", "secret"} {
			check(t, `{"`+key+`":`+value+`}`, JSON, Counts{}, nil)
		}
	}
	for _, value := range []string{`"SYNTHETIC-inert"`, `" "`, `0`, `false`, `true`, `[null]`, `{"empty":""}`} {
		for _, key := range []string{"temp_clone_token", "token", "secret"} {
			check(t, `{"`+key+`":`+value+`}`, JSON, Counts{SecretFields: 1}, nil)
		}
	}
	check(t, `{"Temp_Clone_Token":"SYNTHETIC-inert","TOKEN":false,"Secret":0}`, JSON, Counts{SecretFields: 3}, nil)
	check(t, `{"token_count":7,"secretary":"SYNTHETIC-inert","toKen":"SYNTHETIC-inert"}`, JSON, Counts{}, nil)
	check(t, `{"note":"token","another":"secret"}`, JSON, Counts{}, nil)
}

func TestNestedDuplicateAndEscapedJSON(t *testing.T) {
	check(t, `{"outer":[{"token":"SYNTHETIC-inert"},{"secret":null},{"inner":{"temp_clone_token":false}}]}`, JSON, Counts{SecretFields: 2}, nil)
	check(t, `{"token":"SYNTHETIC-inert","token":""}`, JSON, Counts{SecretFields: 1}, nil)
	check(t, `{"token":"","token":"SYNTHETIC-inert"}`, JSON, Counts{SecretFields: 1}, nil)
	check(t, `{"token":{"secret":"SYNTHETIC-inert"}}`, JSON, Counts{SecretFields: 2}, nil)
	check(t, `{"\u0074oken":"SYNTHETIC-inert","temp\u005fclone_token":""}`, JSON, Counts{SecretFields: 1}, nil)
	check(t, `{"token":"`+fakeClassic+`","note":`+fakeEscaped+`}`, JSON, Counts{GitHubTokens: 2, SecretFields: 1}, nil)
	check(t, `{"`+fakeClassic+`":"SYNTHETIC-inert"}`, JSON, Counts{GitHubTokens: 1}, nil)
	check(t, `{"note":"\\u0074oken","emoji":"\ud83d\ude00"}`, JSON, Counts{}, nil)
	check(t, `{"note":"\"token\":\"SYNTHETIC-inert\""}`, JSON, Counts{}, nil)
	for _, input := range []string{`null`, `""`, `[]`, `{}`, `true`, `0`, `"SYNTHETIC"`} {
		check(t, input, JSON, Counts{}, nil)
	}
}

func TestRefuseMalformedOrIncompleteJSON(t *testing.T) {
	for _, input := range []string{
		``, ` `, `{`, `[`, `{"token":`, `{"token":"SYNTHETIC-inert"`,
		`{"token":"SYNTHETIC-inert",}`, `{"token":"SYNTHETIC-inert"} trailing`,
		`{"token":"SYNTHETIC-inert"} {}`, `{"token":"SYNTHETIC-inert"} ]`,
		`{"token":"SYNTHETIC-inert","bad":01}`, `{"token":"SYNTHETIC-inert","bad":"\q"}`,
		`["SYNTHETIC",]`, `{"token" "SYNTHETIC"}`, `{"token":NaN}`,
	} {
		check(t, input, JSON, Counts{}, ErrJSON)
	}
	// Every proper prefix of a populated JSON object refuses. The valid full
	// document blocks, proving truncated input cannot silently become clear.
	document := `{"token":"SYNTHETIC-inert"}`
	for n := range len(document) {
		check(t, document[:n], JSON, Counts{}, ErrJSON)
	}
	check(t, document, JSON, Counts{SecretFields: 1}, nil)
}

func TestEncodingAndFormats(t *testing.T) {
	for _, format := range []Format{JSON, Auto} {
		for _, input := range []string{"\xff", "{\x00}", "\xef\xbb\xbf{}", "\xff\xfe{\x00}\x00"} {
			check(t, input, format, Counts{}, ErrEncoding)
		}
	}
	for _, input := range []string{`"\ud800"`, `"\udfff"`, `"\ud800x"`, `"\ud800\u0041"`, `"\uZZZZ"`} {
		check(t, input, JSON, Counts{}, ErrEncoding)
	}
	check(t, `{"token":"\u0000"}`, JSON, Counts{SecretFields: 1}, nil)
	check(t, `"\\ud800"`, JSON, Counts{}, nil)
	check(t, "", Auto, Counts{}, nil)
	check(t, `{}`, Format(0), Counts{}, ErrFormat)
	check(t, `{}`, Format(255), Counts{}, ErrFormat)
}

func TestAutoRecognizesJSONRegardlessOfFilename(t *testing.T) {
	check(t, " \n\t"+`{"token":"SYNTHETIC-inert"}`, Auto, Counts{SecretFields: 1}, nil)
	check(t, `[{"secret":false}]`, Auto, Counts{SecretFields: 1}, nil)
	check(t, fakeEscaped, Auto, Counts{GitHubTokens: 1}, nil)
	check(t, `{"token":"SYNTHETIC-inert"`, Auto, Counts{}, ErrJSON)
	check(t, `[`, Auto, Counts{}, ErrJSON)
	check(t, `"SYNTHETIC`, Auto, Counts{}, ErrJSON)
}

func TestBounds(t *testing.T) {
	check(t, strings.Repeat(" ", MaxBytes), JSON, Counts{}, ErrJSON)
	check(t, strings.Repeat(" ", MaxBytes+1), JSON, Counts{}, ErrLimit)
	check(t, strings.Repeat("x", MaxBytes+1), Auto, Counts{}, ErrLimit)
	check(t, strings.Repeat("x", MaxString), Auto, Counts{}, nil)
	check(t, strings.Repeat("x", MaxString+1), Auto, Counts{}, ErrLimit)
	check(t, strings.Repeat("x", MaxString)+"\n"+"x", Auto, Counts{}, nil)
	check(t, `"`+strings.Repeat("x", MaxString)+`"`, JSON, Counts{}, nil)
	check(t, `"`+strings.Repeat("x", MaxString+1)+`"`, JSON, Counts{}, ErrLimit)
	check(t, `{"`+strings.Repeat("x", MaxString+1)+`":null}`, JSON, Counts{}, ErrLimit)
	check(t, strings.Repeat("[", MaxDepth)+"null"+strings.Repeat("]", MaxDepth), JSON, Counts{}, nil)
	check(t, strings.Repeat("[", MaxDepth+1)+"null"+strings.Repeat("]", MaxDepth+1), JSON, Counts{}, ErrLimit)
	check(t, "["+strings.Repeat("0,", MaxValues-2)+"0]", JSON, Counts{}, nil)
	check(t, "["+strings.Repeat("0,", MaxValues-1)+"0]", JSON, Counts{}, ErrLimit)
	check(t, `{"token":"SYNTHETIC-inert","deep":`+strings.Repeat("[", MaxDepth)+"null"+strings.Repeat("]", MaxDepth)+`}`, JSON, Counts{}, ErrLimit)
	// Repeated nested prefixes exercise the bounded token lookahead.
	check(t, strings.Repeat("github_pat_", 10000), Auto, Counts{GitHubTokens: 9992}, nil)
}
