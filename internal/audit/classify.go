package audit

import "strings"

// agentLogins is the fixed, documented list of known coding-agent
// products whose name in a commit author, committer, or Co-authored-by
// trailer marks a commit as agent-authored. Keep this list in sync with
// AGENTS.md's own mentions of tooling if it grows.
var agentLogins = []string{
	"claude",
	"copilot",
	"codex",
	"devin",
	"cursor",
	"jules",
	"aider",
}

// IsBotOrAgentCommit reports whether a commit, identified by its author
// name/email and message trailers, was authored by a bot account or a
// known coding agent.
func IsBotOrAgentCommit(authorName, authorEmail string, trailers map[string][]string) bool {
	if isBotOrAgentIdentity(authorName) || isBotOrAgentIdentity(authorEmail) {
		return true
	}
	for _, v := range trailers["Co-authored-by"] {
		if isBotOrAgentIdentity(v) {
			return true
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
	for _, agent := range agentLogins {
		if strings.Contains(lower, agent) {
			return true
		}
	}
	return false
}
