// Package ui establishes terminal presentation conventions for stet.
//
// The visual style follows a restrained, paper-and-ink aesthetic: high legibility
// across light and dark terminals, crisp margins, muted structure lines, and no
// garish or animated decorations.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// Terminal capability detection.
func IsTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

var (
	// Muted and structural styles.
	Muted = lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#737373", Dark: "#a3a3a3"})

	Bold = lipgloss.NewStyle().
		Bold(true)

	// Status styles.
	SuccessStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#4ade80"})

	WarnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#b45309", Dark: "#fbbf24"})

	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#f87171"})

	// Frame and block styles.
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			MarginBottom(1)

	DividerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#d4d4d4", Dark: "#404040"})

	KeyStyle = lipgloss.NewStyle().
			Bold(true).
			Width(18).
			Foreground(lipgloss.AdaptiveColor{Light: "#404040", Dark: "#d4d4d4"})

	ValStyle = lipgloss.NewStyle()
)

// Header formats a section header.
func Header(title string) string {
	return HeaderStyle.Render(strings.ToUpper(title))
}

// KeyValue renders an aligned key-value pair.
func KeyValue(key, val string) string {
	return fmt.Sprintf("%s %s", KeyStyle.Render(key), ValStyle.Render(val))
}

// Success formats a confirmation message with a checkmark.
func Success(msg string) string {
	return fmt.Sprintf("%s %s", SuccessStyle.Render("✓"), msg)
}

// Warn formats a warning or quarantined message with an exclamation mark.
func Warn(msg string) string {
	return fmt.Sprintf("%s %s", WarnStyle.Render("!"), msg)
}

// Error formats an error message with a cross mark.
func Error(msg string) string {
	return fmt.Sprintf("%s %s", ErrorStyle.Render("✗"), msg)
}

// FprintDivider writes a subtle horizontal rule to w.
func FprintDivider(w io.Writer, width int) error {
	if width <= 0 {
		width = 60
	}
	_, err := fmt.Fprintln(w, DividerStyle.Render(strings.Repeat("─", width)))
	return err
}
