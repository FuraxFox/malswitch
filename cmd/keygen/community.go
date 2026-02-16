package main

import (
	"fmt"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

func doCommunityCreate(ownerPrivKeyFile string, ownerFile string, communityFile string, thresold string) error {

	owner, err := aiq_message.LoadContactFromFile(ownerFile)
	if err != nil {
		return err
	}

	ownerKeys, err := aiq_message.LoadPrivateKeys(ownerPrivKeyFile)
	if err != nil {
		return err
	}

	community, err := aiq.CreateCommunity(owner, thresold)
	if err != nil {
		return err
	}

	err = community.Sign(ownerKeys)
	if err != nil {
		return err
	}

	err = community.Save(communityFile)
	if err != nil {
		return err
	}

	fmt.Printf("Community generation successful for '%s'.\n", communityFile)
	fmt.Printf("UUID: %s\n", community.UUID)

	return nil
}

func doCommunityAppend(ownerPrivKeyFile string, communityFile string, memberFile string) error {
	community, err := aiq.LoadCommunity(communityFile)
	if err != nil {
		return err
	}

	ownerKeys, err := aiq_message.LoadPrivateKeys(ownerPrivKeyFile)
	if err != nil {
		return err
	}

	member, err := aiq_message.LoadContactFromFile(memberFile)
	if err != nil {
		return err
	}

	community.AddContact(member)

	err = community.Sign(ownerKeys)
	if err != nil {
		return err
	}

	err = community.Save(communityFile)
	if err != nil {
		return err
	}

	fmt.Printf("Community update successful for '%s'.\n", communityFile)
	fmt.Printf("UUID: %s\n", community.UUID)

	return nil
}

func doCommunityRemove(ownerPrivKeyFile string, communityFile string, memberFile string) error {
	community, err := aiq.LoadCommunity(communityFile)
	if err != nil {
		return err
	}

	ownerKeys, err := aiq_message.LoadPrivateKeys(ownerPrivKeyFile)
	if err != nil {
		return err
	}

	member, err := aiq_message.LoadContactFromFile(memberFile)
	if err != nil {
		return err
	}

	community.RemoveMember(member)

	err = community.Sign(ownerKeys)
	if err != nil {
		return err
	}

	err = community.Save(communityFile)
	if err != nil {
		return err
	}

	fmt.Printf("Community update successful for '%s'.\n", communityFile)
	fmt.Printf("UUID: %s\n", community.UUID)

	return nil
}
