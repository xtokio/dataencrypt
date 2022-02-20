package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	_ "github.com/mattn/go-sqlite3"
	"github.com/thanhpk/randstr"
)

// Use of random bytes
var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, secret string) (string, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, secret string) (string, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func insert(db *sql.DB, message string, secret string) string {
	query_insert := `INSERT INTO messages(message, secret, decrypted, link, created_at) VALUES (?, ?, ?, ?, ?)`
	// Prepare statement.
	statement, err := db.Prepare(query_insert)
	if err != nil {
		log.Fatalln(err.Error())
	}

	decrypted := 0
	link := randstr.String(32)
	created_at := time.Now()

	_, err = statement.Exec(message, secret, decrypted, link, created_at.Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Fatalln(err.Error())
	}
	return link
}

func main() {
	sqliteDatabase, _ := sql.Open("sqlite3", "./dataencrypt.db")
	defer sqliteDatabase.Close() // Defer Closing the database

	app := fiber.New()
	app.Static("/", "./public")

	type ParamsEncrypt struct {
		Message string `json:"message"`
		Secret  string `json:"secret"`
	}

	app.Post("/api/encrypt", func(c *fiber.Ctx) error {
		params := new(ParamsEncrypt)
		if err := c.BodyParser(params); err != nil {
			return err
		}

		// Encrypt message
		encText, err := Encrypt(params.Message, params.Secret)
		if err != nil {
			return c.JSON(&fiber.Map{
				"success":        false,
				"message":        params.Message,
				"encrypted":      "",
				"link":           "",
				"error_response": "error encrypting your message: " + err.Error(),
			})
		}

		// Insert into DB
		link := insert(sqliteDatabase, encText, params.Secret)

		// Return JSON
		return c.JSON(&fiber.Map{
			"success":        true,
			"message":        params.Message,
			"encrypted":      encText,
			"link":           link,
			"error_response": "",
		})
	})

	log.Fatal(app.Listen(":3000"))
}
