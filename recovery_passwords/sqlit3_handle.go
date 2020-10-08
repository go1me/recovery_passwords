package recovery_passwords

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type Mysqldb struct {
	Sqldb *sql.DB
}

func ConnectDB(path string) (*Mysqldb, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &Mysqldb{db}, nil
}

func (p Mysqldb) Close() {
	p.Sqldb.Close()
}

func (p Mysqldb) ReadTable_chrome_Logins() ([]Logins_table_struct, error) {
	logins_table_struct := Logins_table_struct{}
	logins_table_struct_list := []Logins_table_struct{}
	selectDML := "SELECT Origin_url,username_value,password_value FROM Logins"

	stmt, err := p.Sqldb.Prepare(selectDML)
	if err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&logins_table_struct.Origin_url,
			&logins_table_struct.Username_value,
			&logins_table_struct.Password_value)
		if err != nil {
			log.Println(err)
		} else {
			logins_table_struct_list = append(logins_table_struct_list, logins_table_struct)
		}
	}

	if err := rows.Err(); err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	return logins_table_struct_list, nil

}

func (p Mysqldb) ReadTable_mailbird_accounts() ([]Logins_table_struct, error) {
	logins_table_struct := Logins_table_struct{}
	logins_table_struct_list := []Logins_table_struct{}
	selectDML := "SELECT Server_Host,Username,EncrypatedPassword FROM Accounts"

	stmt, err := p.Sqldb.Prepare(selectDML)
	if err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&logins_table_struct.Origin_url,
			&logins_table_struct.Username_value,
			&logins_table_struct.Password_value)
		if err != nil {
			log.Println(err)
		} else {
			logins_table_struct_list = append(logins_table_struct_list, logins_table_struct)
		}
	}

	if err := rows.Err(); err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	return logins_table_struct_list, nil

}

func (p Mysqldb) ReadTable_mailbird_senderIdentities() ([]Logins_table_struct, error) {
	logins_table_struct := Logins_table_struct{}
	logins_table_struct_list := []Logins_table_struct{}
	var password sql.NullString
	selectDML := "SELECT Server_Host,Email,EncrypatedPassword FROM SenderIdentities"

	stmt, err := p.Sqldb.Prepare(selectDML)
	if err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&logins_table_struct.Origin_url,
			&logins_table_struct.Username_value,
			&password)
		if err != nil {
			log.Println(err)
		} else {
			logins_table_struct.Password_value = password.String
			logins_table_struct_list = append(logins_table_struct_list, logins_table_struct)
		}
	}

	if err := rows.Err(); err != nil {
		log.Println(err)
		return logins_table_struct_list, err
	}
	return logins_table_struct_list, nil

}

func getDecryptKey(FirefoxKey4File string) (item1, item2, a11, a102 []byte, err error) {
	var (
		keyDB   *sql.DB
		pwdRows *sql.Rows
		nssRows *sql.Rows
	)
	keyDB, err = sql.Open("sqlite3", FirefoxKey4File)
	if err != nil {
		log.Println(err)
		return nil, nil, nil, nil, err
	}
	defer func() {
		if err := keyDB.Close(); err != nil {
			log.Println(err)
		}
	}()

	pwdRows, err = keyDB.Query(`SELECT item1, item2 FROM metaData WHERE id = 'password'`)
	defer func() {
		if err := pwdRows.Close(); err != nil {
			log.Println(err)
		}
	}()
	for pwdRows.Next() {
		if err := pwdRows.Scan(&item1, &item2); err != nil {
			log.Println(err)
			continue
		}
	}
	if err != nil {
		log.Println(err)
	}
	nssRows, err = keyDB.Query(`SELECT a11, a102 from nssPrivate`)
	defer func() {
		if err := nssRows.Close(); err != nil {
			log.Println(err)
		}
	}()
	for nssRows.Next() {
		if err := nssRows.Scan(&a11, &a102); err != nil {
			log.Println(err)
		}
	}
	return item1, item2, a11, a102, nil
}
