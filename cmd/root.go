package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "hunter",
	Short: "Audit your REST API like Lighthouse does for the Web",
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
