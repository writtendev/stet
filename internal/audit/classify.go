package audit

import "strings"

// agentWords are known coding-agent product names matched as a
// standalone word (not a substring inside a longer word) in an author or
// committer name, an email address, a Co-authored-by trailer, or a
// GitHub login. They are limited to names distinctive enough that an
// ordinary human is unlikely to share them outright -- "claudette" or
// "cursorwalker" must not match "claude"/"cursor".
var agentWords = []string{
	"claude",
	"copilot",
	"codex",
	"cursor",
	"aider",
}

// agentIdentifiers are precise substrings -- bot login fragments or email
// domains -- for agents whose product name doubles as a common human
// first name ("Devin", "Jules"). Those are matched only by their known
// account signature, never as a generic name word, so "Devin Park" and
// "Jules Martin" are not misclassified as agents.
var agentIdentifiers = []string{
	"devin-ai-integration", // Devin (Cognition)
	"google-labs-jules",    // Jules (Google)
}

// IsBotOrAgentCommit reports whether a commit, identified by its author
// and committer name/email and message trailers, was authored by a bot
// account or a known coding agent. The committer is checked too, since a
// bot or agent can commit on a human's behalf (e.g. a CI bot as
// committer with a human author).
func IsBotOrAgentCommit(authorName, authorEmail, committerName, committerEmail string, trailers map[string][]string) bool {
	for _, s := range []string{authorName, authorEmail, committerName, committerEmail} {
		if isBotOrAgentIdentity(s) {
			return true
		}
	}
	for key, values := range trailers {
		if !strings.EqualFold(key, "Co-authored-by") {
			continue
		}
		for _, v := range values {
			if isBotOrAgentIdentity(v) {
				return true
			}
		}
	}
	return false
}

// IsBotOrAgentLogin reports whether a GitHub login/account, given its
// GraphQL __typename ("Bot" or not), is a bot or known agent.
func IsBotOrAgentLogin(login string, isBotType bool) bool {
	return isBotType || isBotOrAgentIdentity(login)
}

func isBotOrAgentIdentity(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "[bot]") {
		return true
	}
	for _, id := range agentIdentifiers {
		if strings.Contains(lower, id) {
			return true
		}
	}
	for _, word := range agentWords {
		if containsWord(lower, word) {
			return true
		}
	}
	return false
}

// containsWord reports whether word appears in s bounded by non-word
// characters (or the string's edges), so "claude" matches "Claude
// <noreply@anthropic.com>" but not "claudette@example.com", and "cursor"
// matches "Cursor Agent" but not "cursorwalker".
func containsWord(s, word string) bool {
	for start := 0; ; {
		i := strings.Index(s[start:], word)
		if i < 0 {
			return false
		}
		begin := start + i
		end := begin + len(word)
		if (begin == 0 || !isWordByte(s[begin-1])) && (end == len(s) || !isWordByte(s[end])) {
			return true
		}
		start = begin + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}
