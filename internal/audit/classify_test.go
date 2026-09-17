package audit

import "testing"

func TestIsBotOrAgentCommit(t *testing.T) {
	cases := []struct {
		name           string
		author         string
		email          string
		committerName  string
		committerEmail string
		trailers       map[string][]string
		want           bool
	}{
		{"human", "Alice Example", "alice@example.com", "Alice Example", "alice@example.com", nil, false},
		{"github actions bot suffix", "github-actions[bot]", "github-actions[bot]@users.noreply.github.com", "github-actions[bot]", "github-actions[bot]@users.noreply.github.com", nil, true},
		{"dependabot", "dependabot[bot]", "dependabot@users.noreply.github.com", "dependabot[bot]", "dependabot@users.noreply.github.com", nil, true},
		{"agent name in author", "Claude", "noreply@anthropic.com", "Claude", "noreply@anthropic.com", nil, true},
		{"agent in co-author trailer", "Alice Example", "alice@example.com", "Alice Example", "alice@example.com",
			map[string][]string{"Co-authored-by": {"Claude <noreply@anthropic.com>"}}, true},
		{"co-authored-by trailer is case-insensitive", "Alice Example", "alice@example.com", "Alice Example", "alice@example.com",
			map[string][]string{"Co-Authored-By": {"Claude <noreply@anthropic.com>"}}, true},
		{"unrelated trailer", "Alice Example", "alice@example.com", "Alice Example", "alice@example.com",
			map[string][]string{"Signed-off-by": {"Alice Example <alice@example.com>"}}, false},
		{"substring inside a longer word does not match", "Nicholas Claudel", "nick@example.com", "Nicholas Claudel", "nick@example.com", nil, false},
		{"claudette email local-part is not claude", "Alice Example", "claudette@example.com", "Alice Example", "claudette@example.com", nil, false},
		{"cursorwalker login-like name is not cursor", "cursorwalker", "cursorwalker@example.com", "cursorwalker", "cursorwalker@example.com", nil, false},
		{"aiderson name is not aider", "Aiderson Smith", "aiderson@example.com", "Aiderson Smith", "aiderson@example.com", nil, false},
		{"human named Devin is not the Devin agent", "Devin Park", "devin.park@example.com", "Devin Park", "devin.park@example.com", nil, false},
		{"human named Jules is not the Jules agent", "Jules Martin", "jules.martin@example.com", "Jules Martin", "jules.martin@example.com", nil, false},
		{"real devin bot login carries its own identifier", "devin-ai-integration[bot]", "devin-ai-integration[bot]@users.noreply.github.com", "devin-ai-integration[bot]", "devin-ai-integration[bot]@users.noreply.github.com", nil, true},
		{"real jules bot login carries its own identifier", "google-labs-jules[bot]", "jules@google.com", "google-labs-jules[bot]", "jules@google.com", nil, true},
		{"bot as committer only, human author", "Alice Example", "alice@example.com", "github-actions[bot]", "github-actions[bot]@users.noreply.github.com", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBotOrAgentCommit(tc.author, tc.email, tc.committerName, tc.committerEmail, tc.trailers)
			if got != tc.want {
				t.Errorf("IsBotOrAgentCommit(%q, %q, %q, %q, %v) = %v, want %v", tc.author, tc.email, tc.committerName, tc.committerEmail, tc.trailers, got, tc.want)
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
	if IsBotOrAgentLogin("cursorwalker", false) {
		t.Error("expected a login merely containing 'cursor' as a substring to not classify as an agent")
	}
	if IsBotOrAgentLogin("devin-park", false) {
		t.Error("expected a human-named login to not classify as the Devin agent")
	}
}
