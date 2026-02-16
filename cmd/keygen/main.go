package main

import (
	"fmt"
	"log"
	"os"
)

func usage(commandname string) {
	fmt.Printf("%s - a tool to manage keys, contacts and communities for AIQ system\n", commandname)
	fmt.Println("\nUsage:")
	fmt.Printf("   %s keygen  <contact_name>\n", commandname)
	fmt.Printf("   %s contgen <contact_name> <contact endpoint>\n", commandname)
	fmt.Printf("   %s comcrea <owner private key file>  <owner contact file>> <threshold> <community file>\n", commandname)
	fmt.Printf("   %s comadd  <owner private key file> <community file> <member_signature_pubkey_file> <member_encryption_pubkey_file> <member endpoint>\n", commandname)
	fmt.Printf("   %s comdel  <owner private key file> <community file> <member_signature_pubkey_file> <member_encryption_pubkey_file>\n", commandname)
	fmt.Println("\nExample: ")
	fmt.Printf("   %s keygen Alice  \n", commandname)
	fmt.Printf("   %s contcrea Alice 'https://:8888' \n", commandname)
	fmt.Printf("   %s comcrea owner_key.priv mycommunity.cmy \n", commandname)
	fmt.Printf("   %s comadd  owner_key.priv  mycommunity.cmy bob.ctc \n", commandname)
	fmt.Printf("   %s comdel  owner_key.priv  mycommunity.cmy bob.ctc \n", commandname)
	fmt.Println("")
}

func main() {
	if len(os.Args) < 2 {
		commandname := os.Args[0]
		usage(commandname)
		os.Exit(1)
	}

	action := os.Args[1]

	switch action {
	case "keygen":
		contactName := os.Args[2]
		err := doKeyGen(contactName)
		if err != nil {
			log.Fatalf("Error while generating key for '%s' : %v", contactName, err)
		}
	case "contcrea":
		contactName := os.Args[2]
		contactEndpoint := os.Args[3]
		err := doContactGen(contactName, contactEndpoint)
		if err != nil {
			log.Fatalf("Error while generating contact for '%s' : %v", contactName, err)
		}

	case "comcrea":
		ownerKey := os.Args[2]
		ownerFile := os.Args[3]
		thresold := os.Args[4]
		communityFile := os.Args[5]

		err := doCommunityCreate(ownerKey, ownerFile, communityFile, thresold)
		if err != nil {
			log.Fatalf("Failed to create community '%s' : %v", communityFile, err)
		}
	case "comadd":
		ownerKey := os.Args[2]
		communityFile := os.Args[3]
		memberFile := os.Args[4]

		err := doCommunityAppend(ownerKey, communityFile, memberFile)
		if err != nil {
			log.Fatalf("Failed to add member do community '%s' : %v", communityFile, err)
		}

	case "comdel":
		ownerKey := os.Args[2]
		communityFile := os.Args[3]
		memberFile := os.Args[4]

		err := doCommunityRemove(ownerKey, communityFile, memberFile)
		if err != nil {
			log.Fatalf("Failed to delete member from community '%s' : %v", communityFile, err)
		}
	default:
		commandname := os.Args[0]
		usage(commandname)

		log.Fatalf("Un supported option '%s' ", action)
	}

}
