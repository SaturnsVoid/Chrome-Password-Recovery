//Chrome Password Recovery project main.go
//Recover Websites, Username and Passwords from Google Chromes Login Data file.

//Windows Only

//SQLLite3 - github.com/mattn/go-sqlite3
//Using Crypt32.dll (win32crypt) for decryption

//C:\Users\{USERNAME}\AppData\Local\Google\Chrome\User Data\Default

package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")

	dataPath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func copyFileToDirectory(pathSourceFile string, pathDestFile string) error {
	sourceFile, err := os.Open(pathSourceFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(pathDestFile)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}

	sourceFileInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	destFileInfo, err := destFile.Stat()
	if err != nil {
		return err
	}

	if sourceFileInfo.Size() == destFileInfo.Size() {
	} else {
		return err
	}
	return nil
}

func checkFileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func main() {
	//Check for Login Data file
	if !checkFileExist(dataPath) {
		os.Exit(0)
	}

	//Copy Login Data file to temp location
	err := copyFileToDirectory(dataPath, os.Getenv("APPDATA")+"\\tempfile.dat")
	if err != nil {
		log.Fatal(err)
	}

	//Open Database
	db, err := sql.Open("sqlite3", os.Getenv("APPDATA")+"\\tempfile.dat")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//Select Rows to get data from
	rows, err := db.Query("select origin_url, username_value, password_value from logins")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var URL string
		var USERNAME string
		var PASSWORD string

		err = rows.Scan(&URL, &USERNAME, &PASSWORD)
		if err != nil {
			log.Fatal(err)
		}
		//Decrypt Passwords
		pass, err := Decrypt([]byte(PASSWORD))
		if err != nil {
			log.Fatal(err)
		}
		//Check if no value, if none skip
		if URL != "" && URL != "" && string(pass) != "" {
			fmt.Println(URL, USERNAME, string(pass))
		}
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

}
