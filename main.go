package main
import(
	"fmt"
	"./recovery_passwords"
)

func merage_map(map1,map2 map[string][]recovery_passwords.Logins_table_struct)(map[string][]recovery_passwords.Logins_table_struct){
	for k,v := range map2{
		if _, ok := map1[k]; ok {
			map1[k] = append(map1[k],v...)
		}else{
			map1[k] = v
		}
	}
	return map1
}

func main(){
	result_map := make(map[string][]recovery_passwords.Logins_table_struct)
	result_map = merage_map(result_map,recovery_passwords.Recovery_passwords_chromes()) //ok
	result_map = merage_map(result_map,recovery_passwords.Recovery_passwords_Mailbirds()) //ok

	fmt.Println(result_map)
	fmt.Println("---------------------------------------")
	for k,result := range result_map{
		fmt.Println("------------"+k+"-----------")
		for _, data := range result{
			fmt.Println(data.Origin_url,"	",data.Username_value,"	",data.Password_value)
		}
	}
}
