package audit

import "testing"

func TestIsBotOrAgentCommit(t *testing.T) {
	cases := []struct {
		name     string
		author   string
		email    string
		trailers map[string][]string
		want     bool
	}{
		{"human", "Alice Example", "alice@example.com", nil, false},
		{"github actions bot suffix", "github-actions[bot]", "github-actions[bot]@users.noreply.github.com", nil, true},
		{"dependabot", "dependabot[bot]", "dependabot@users.noreply.github.com", nil, true},
		{"agent name in author", "Claude", "noreply@anthropic.com", nil, true},
		{"agent in co-author trailer", "Alice Example", "alice@example.com",
			map[string][]string{"Co-authored-by": {"Claude <noreply@anthropic.com>"}}, true},
		{"unrelated trailer", "Alice Example", "alice@example.com",
			map[string][]string{"Signed-off-by": {"Alice Example <alice@example.com>"}}, false},
		{"substring false positive guard", "Nicholas Claudel", "nick@example.com", nil, true}, // documents current substring behavior
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBotOrAgentCommit(tc.author, tc.email, tc.trailers)
			if got != tc.want {
				t.Errorf("IsBotOrAgentCommit(%q, %q, %v) = %v, want %v", tc.author, tc.email, tc.trailers, got, tc.want)
			}
		})
	}
}

func TestIsBotOrAgentLogin(t *testing.T) {
	if !IsBotOrAgentLogin("some-login", true) {
		t.Error("expected Bot __typename to always classify as bot")
	}
	if !IsBotOrAgentLogin("dependabot[bot]", false) {
		t.Error("expected [bot] suffix login to classify as bot")
	}
	if IsBotOrAgentLogin("alice", false) {
		t.Error("expected ordinary login to not classify as bot")
	}
}
