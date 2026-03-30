package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sql.DB
}

func InitDB(filepath string) (*Database, error) {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Create tables
	queries := []string{
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			raw_message TEXT NOT NULL,
			reception_time INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS deliveries (
			message_id INTEGER NOT NULL,
			recipient_pubkey TEXT NOT NULL,
			delivery_time INTEGER,
			PRIMARY KEY (message_id, recipient_pubkey),
			FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
		);`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return nil, fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return &Database{db: db}, nil
}

func (d *Database) SaveMessage(rawMsg []byte) error {
	var msg aiq_message.EncryptedMessage
	if err := json.Unmarshal(rawMsg, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal message for storage: %w", err)
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO messages (raw_message, reception_time) VALUES (?, ?)", string(rawMsg), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to insert message: %w", err)
	}

	msgID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	for _, pubkey := range msg.RecipientKeys {
		if _, err := tx.Exec("INSERT INTO deliveries (message_id, recipient_pubkey) VALUES (?, ?)", msgID, pubkey); err != nil {
			return fmt.Errorf("failed to insert delivery: %w", err)
		}
	}

	return tx.Commit()
}

func (d *Database) GetUndeliveredMessages(recipientPubKey string) ([]aiq_message.EncryptedMessage, []int64, error) {
	query := `
		SELECT m.id, m.raw_message
		FROM messages m
		JOIN deliveries d ON m.id = d.message_id
		WHERE d.recipient_pubkey = ? AND d.delivery_time IS NULL
		ORDER BY m.reception_time ASC
	`
	rows, err := d.db.Query(query, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var messages []aiq_message.EncryptedMessage
	var ids []int64
	for rows.Next() {
		var id int64
		var raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, nil, err
		}

		var msg aiq_message.EncryptedMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			continue // Skip corrupted messages
		}
		messages = append(messages, msg)
		ids = append(ids, id)
	}

	return messages, ids, nil
}

func (d *Database) MarkAsDelivered(recipientPubKey string, messageIDs []int64) error {
	if len(messageIDs) == 0 {
		return nil
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := "UPDATE deliveries SET delivery_time = ? WHERE recipient_pubkey = ? AND message_id = ?"
	now := time.Now().Unix()
	for _, id := range messageIDs {
		if _, err := tx.Exec(query, now, recipientPubKey, id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (d *Database) CleanupMessages(maxAge int) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 1. Delete messages where all recipients have been served
	res1, err := tx.Exec(`
		DELETE FROM messages
		WHERE id NOT IN (
			SELECT message_id FROM deliveries WHERE delivery_time IS NULL
		)
	`)
	if err != nil {
		return 0, err
	}
	deleted1, _ := res1.RowsAffected()

	// 2. Delete messages beyond max_age
	res2, err := tx.Exec("DELETE FROM messages WHERE reception_time < ?", time.Now().Unix()-int64(maxAge))
	if err != nil {
		return 0, err
	}
	deleted2, _ := res2.RowsAffected()

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return deleted1 + deleted2, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}
