package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	// Define Subcommands using FlagSets
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	keygenName := keygenCmd.String("name", "", "Contact name (Required)")

	contcreaCmd := flag.NewFlagSet("contcrea", flag.ExitOnError)
	contName := contcreaCmd.String("name", "", "Contact name (Required)")
	contEnd := contcreaCmd.String("endpoint", "", "Contact endpoint URL (Required)")

	comcreaCmd := flag.NewFlagSet("comcrea", flag.ExitOnError)
	comCreaOwnerKey := comcreaCmd.String("owner-key", "", "Owner private key file (Required)")
	comCreaOwnerCont := comcreaCmd.String("owner-cont", "", "Owner contact file (Required)")
	comCreaThreshold := comcreaCmd.String("threshold", "1", "Threshold value")
	comCreaFile := comcreaCmd.String("file", "", "Community file output (Required)")

	comaddCmd := flag.NewFlagSet("comadd", flag.ExitOnError)
	comAddOwnerKey := comaddCmd.String("owner-key", "", "Owner private key file (Required)")
	comAddFile := comaddCmd.String("file", "", "Community file (Required)")
	comAddMember := comaddCmd.String("member", "", "Member contact file (Required)")

	comdelCmd := flag.NewFlagSet("comdel", flag.ExitOnError)
	comDelOwnerKey := comdelCmd.String("owner-key", "", "Owner private key file (Required)")
	comDelFile := comdelCmd.String("file", "", "Community file (Required)")
	comDelMember := comdelCmd.String("member", "", "Member contact file (Required)")

	// Check if an action was provided
	if len(os.Args) < 2 {
		printGlobalUsage()
		os.Exit(1)
	}

	// Switch on the subcommand
	switch os.Args[1] {

	case "keygen":
		keygenCmd.Parse(os.Args[2:])
		if *keygenName == "" {
			keygenCmd.Usage()
			os.Exit(1)
		}
		handleError(doKeyGen(*keygenName), "keygen")

	case "contcrea":
		contcreaCmd.Parse(os.Args[2:])
		if *contName == "" || *contEnd == "" {
			contcreaCmd.Usage()
			os.Exit(1)
		}
		handleError(doContactGen(*contName, *contEnd), "contcrea")

	case "comcrea":
		comcreaCmd.Parse(os.Args[2:])
		if *comCreaOwnerKey == "" || *comCreaFile == "" {
			comcreaCmd.Usage()
			os.Exit(1)
		}
		handleError(doCommunityCreate(*comCreaOwnerKey, *comCreaOwnerCont, *comCreaFile, *comCreaThreshold), "comcrea")

	case "comadd":
		comaddCmd.Parse(os.Args[2:])
		if *comAddOwnerKey == "" || *comAddFile == "" || *comAddMember == "" {
			comaddCmd.Usage()
			os.Exit(1)
		}
		handleError(doCommunityAppend(*comAddOwnerKey, *comAddFile, *comAddMember), "comadd")

	case "comdel":
		comdelCmd.Parse(os.Args[2:])
		if *comDelOwnerKey == "" || *comDelFile == "" || *comDelMember == "" {
			comdelCmd.Usage()
			os.Exit(1)
		}
		handleError(doCommunityRemove(*comDelOwnerKey, *comDelFile, *comDelMember), "comdel")

	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printGlobalUsage()
		os.Exit(1)
	}
}

// Helper to reduce boilerplate error checking
func handleError(err error, cmd string) {
	if err != nil {
		log.Fatalf("Error during %s: %v", cmd, err)
	}
}

func printGlobalUsage() {
	fmt.Printf("AIQ System Management Tool\n\n")
	fmt.Println("Usage: program <subcommand> [flags]")
	fmt.Println("\nAvailable Subcommands:")
	fmt.Println("  keygen   Generate keys for a new contact")
	fmt.Println("  contcrea Create a contact file")
	fmt.Println("  comcrea  Initialize a new community")
	fmt.Println("  comadd   Add a member to a community")
	fmt.Println("  comdel   Remove a member from a community")
	fmt.Println("\nUse 'program <subcommand> -h' for more information on a command.")
}
