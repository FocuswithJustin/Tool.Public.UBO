package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ubo/internal/config"

	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// fieldDef binds a label, placeholder, and config get/set functions to a text field.
type fieldDef struct {
	label       string
	placeholder string
	section     string // section header shown above this field ("" = no header)
	getValue    func(*config.Config) string
	setValue    func(*config.Config, string)
}

var fields = []fieldDef{
	{
		label: "Host", placeholder: "192.168.1.100", section: "",
		getValue: func(c *config.Config) string { return c.Host },
		setValue: func(c *config.Config, v string) { c.Host = v },
	},
	{
		label: "SSH User", placeholder: "root", section: "SSH",
		getValue: func(c *config.Config) string { return c.SSH.User },
		setValue: func(c *config.Config, v string) { c.SSH.User = v },
	},
	{
		label: "SSH Port", placeholder: "22", section: "",
		getValue: func(c *config.Config) string { return strconv.Itoa(c.SSH.Port) },
		setValue: func(c *config.Config, v string) {
			if n, err := strconv.Atoi(v); err == nil {
				c.SSH.Port = n
			}
		},
	},
	{
		label: "SSH Key Path", placeholder: "(empty = use agent/defaults)", section: "",
		getValue: func(c *config.Config) string { return c.SSH.Key },
		setValue: func(c *config.Config, v string) { c.SSH.Key = v },
	},
	{
		label: "WireGuard Port", placeholder: "51820", section: "WireGuard",
		getValue: func(c *config.Config) string { return strconv.Itoa(c.WireGuard.Port) },
		setValue: func(c *config.Config, v string) {
			if n, err := strconv.Atoi(v); err == nil {
				c.WireGuard.Port = n
			}
		},
	},
	{
		label: "WG Server IP", placeholder: "10.42.0.1/24", section: "",
		getValue: func(c *config.Config) string { return c.WireGuard.ServerIP },
		setValue: func(c *config.Config, v string) { c.WireGuard.ServerIP = v },
	},
	{
		label: "WG Client IP", placeholder: "10.42.0.2/32", section: "",
		getValue: func(c *config.Config) string { return c.WireGuard.ClientIP },
		setValue: func(c *config.Config, v string) { c.WireGuard.ClientIP = v },
	},
	{
		label: "Dropbear Port", placeholder: "22", section: "Dropbear",
		getValue: func(c *config.Config) string { return strconv.Itoa(c.Dropbear.Port) },
		setValue: func(c *config.Config, v string) {
			if n, err := strconv.Atoi(v); err == nil {
				c.Dropbear.Port = n
			}
		},
	},
	{
		label: "Output Dir", placeholder: "(auto: ./ubo-<host>/)", section: "Output",
		getValue: func(c *config.Config) string { return c.Output.Dir },
		setValue: func(c *config.Config, v string) { c.Output.Dir = v },
	},
	{
		label: "Network Interface", placeholder: "(auto-detect)", section: "Network",
		getValue: func(c *config.Config) string { return c.Network.Interface },
		setValue: func(c *config.Config, v string) { c.Network.Interface = v },
	},
	{
		label: "Network IP", placeholder: "(auto-detect, e.g. 192.168.1.100/24)", section: "",
		getValue: func(c *config.Config) string { return c.Network.IP },
		setValue: func(c *config.Config, v string) { c.Network.IP = v },
	},
	{
		label: "LUKS Device", placeholder: "(auto-detect from /etc/crypttab)", section: "LUKS",
		getValue: func(c *config.Config) string { return c.LUKS.Device },
		setValue: func(c *config.Config, v string) { c.LUKS.Device = v },
	},
}

// styles
var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
	sectionStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("241")).PaddingTop(1)
	labelStyle    = lipgloss.NewStyle().Width(20).Foreground(lipgloss.Color("246"))
	activeLabelStyle = lipgloss.NewStyle().Width(20).Foreground(lipgloss.Color("212")).Bold(true)
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	savedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).PaddingTop(1)
	confirmStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
)

type model struct {
	inputs      []textinput.Model
	focusIdx    int
	cfg         *config.Config
	configPath  string
	dirty       bool
	confirmQuit bool
	err         string
	saved       bool
}

func newModel(configPath string) (*model, error) {
	var cfg *config.Config
	if _, err := os.Stat(configPath); err == nil {
		loaded, err := config.Load(configPath)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		cfg = loaded
	} else {
		cfg = config.Default()
	}

	inputs := make([]textinput.Model, len(fields))
	for i, fd := range fields {
		ti := textinput.New()
		ti.Placeholder = fd.placeholder
		ti.CharLimit = 256
		val := fd.getValue(cfg)
		ti.SetValue(val)
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}

	return &model{
		inputs:     inputs,
		focusIdx:   0,
		cfg:        cfg,
		configPath: configPath,
	}, nil
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Confirm quit dialog
		if m.confirmQuit {
			switch msg.String() {
			case "y", "Y":
				if err := m.save(); err != nil {
					m.err = err.Error()
					m.confirmQuit = false
					return m, nil
				}
				return m, tea.Quit
			case "n", "N", "esc", "ctrl+c":
				m.confirmQuit = false
				return m, nil
			case "enter":
				// Default Y — save
				if err := m.save(); err != nil {
					m.err = err.Error()
					m.confirmQuit = false
					return m, nil
				}
				return m, tea.Quit
			}
			return m, nil
		}

		switch msg.String() {
		case "ctrl+c":
			if m.dirty {
				m.confirmQuit = true
				return m, nil
			}
			return m, tea.Quit

		case "esc":
			if m.dirty {
				m.confirmQuit = true
				return m, nil
			}
			return m, tea.Quit

		case "ctrl+s":
			m.err = ""
			if err := m.save(); err != nil {
				m.err = err.Error()
			} else {
				m.saved = true
				m.dirty = false
			}
			return m, nil

		case "tab", "down":
			m.inputs[m.focusIdx].Blur()
			m.focusIdx = (m.focusIdx + 1) % len(m.inputs)
			m.inputs[m.focusIdx].Focus()
			return m, textinput.Blink

		case "shift+tab", "up":
			m.inputs[m.focusIdx].Blur()
			m.focusIdx = (m.focusIdx - 1 + len(m.inputs)) % len(m.inputs)
			m.inputs[m.focusIdx].Focus()
			return m, textinput.Blink
		}

	case tea.WindowSizeMsg:
		return m, nil
	}

	// Update the focused input
	var cmd tea.Cmd
	prev := m.inputs[m.focusIdx].Value()
	m.inputs[m.focusIdx], cmd = m.inputs[m.focusIdx].Update(msg)
	if m.inputs[m.focusIdx].Value() != prev {
		m.dirty = true
		m.saved = false
		m.err = ""
	}

	return m, cmd
}

func (m model) View() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("UBO Configuration Editor"))
	sb.WriteString("  ")
	sb.WriteString(helpStyle.Render("ctrl+s save   esc quit"))
	sb.WriteString("\n\n")

	for i, fd := range fields {
		if fd.section != "" {
			sb.WriteString(sectionStyle.Render(fd.section))
			sb.WriteString("\n")
		}

		var lbl string
		if i == m.focusIdx {
			lbl = activeLabelStyle.Render(fd.label)
		} else {
			lbl = labelStyle.Render(fd.label)
		}
		sb.WriteString("  ")
		sb.WriteString(lbl)
		sb.WriteString("  ")
		sb.WriteString(m.inputs[i].View())
		sb.WriteString("\n")
	}

	sb.WriteString("\n")

	if m.confirmQuit {
		sb.WriteString(confirmStyle.Render("Save before exit? [Y/n]: "))
	} else if m.err != "" {
		sb.WriteString(errorStyle.Render("error: " + m.err))
	} else if m.saved {
		sb.WriteString(savedStyle.Render("saved to " + m.configPath))
	} else {
		sb.WriteString(helpStyle.Render("tab/↑↓ navigate   ctrl+s save   esc quit"))
	}

	return sb.String()
}

// save validates the current inputs, applies them to the config, and writes
// atomically to the config path.
func (m *model) save() error {
	// Apply input values to config
	for i, fd := range fields {
		fd.setValue(m.cfg, m.inputs[i].Value())
	}

	// Validate
	if err := m.cfg.Validate(); err != nil {
		return err
	}

	// Write to temp file then rename (atomic)
	dir := filepath.Dir(m.configPath)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".ubo-*.toml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath) // no-op if rename succeeded
	}()

	enc := toml.NewEncoder(tmp)
	if err := enc.Encode(m.cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, m.configPath); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	return nil
}

// Run opens the interactive TUI for editing configPath.
// If configPath exists it is pre-loaded; otherwise defaults are used.
func Run(configPath string) error {
	m, err := newModel(configPath)
	if err != nil {
		return err
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// If the program exited without saving (no confirmQuit path), we're done.
	_ = finalModel
	return nil
}
