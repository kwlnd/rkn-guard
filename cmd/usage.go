package main

import "github.com/spf13/cobra"

// Русский вариант стандартного шаблона cobra.
const usageTemplate = `Использование:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} <команда>{{end}}{{if gt (len .Aliases) 0}}

Другие имена:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Примеры:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Команды:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Флаги:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Общие флаги:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

Подробнее о команде: {{.CommandPath}} <команда> --help{{end}}
`

func localize(root *cobra.Command) {
	root.SetUsageTemplate(usageTemplate)
	root.InitDefaultHelpFlag()
	root.InitDefaultVersionFlag()
	root.Flags().Lookup("help").Usage = "справка"
	root.Flags().Lookup("version").Usage = "версия"
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		switch c.Name() {
		case "help":
			c.Short = "Справка по команде"
		case "completion":
			c.Short = "Автодополнение для bash, zsh, fish, powershell"
		}
	}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.InitDefaultHelpFlag()
		if f := c.Flags().Lookup("help"); f != nil {
			f.Usage = "справка"
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}
