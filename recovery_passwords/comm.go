package recovery_passwords
import(
	"log"
	"io"
	"os"
	"regexp"
	"io/ioutil"
)

type Browser_info struct{
	Browser_path string
	Need_to_recovery bool
}

type Logins_table_struct struct{
	Origin_url string
	Action_url string
	Username_value string
	Password_value string
	Date_created string
	Password_type int
	Times_used int
}

var(
	Local_appdata = os.Getenv("LOCALAPPDATA")
	Appdata = os.Getenv("APPDATA")
)

//判断文件或者文件夹是否存在
func PathExists(path string)(bool,error){
	_,err := os.Stat(path)
	if err == nil{
		return true,nil
	}
	if os.IsNotExist(err){
		return false,nil
	}
	return false,err
}

func CopyFile(source, dest string) bool {
	if source == "" || dest == "" {
		log.Println("source or dest is null")
		return false
	}
	//打开文件资源
	source_open, err := os.Open(source)
	//养成好习惯。操作文件时候记得添加 defer 关闭文件资源代码
	if err != nil {
		log.Println(err.Error())
		return false
	}
	defer source_open.Close()
	//只写模式打开文件 如果文件不存在进行创建 并赋予 644的权限。详情查看linux 权限解释
	dest_open, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 644)
	if err != nil {
		log.Println(err.Error())
		return false
	}
	//养成好习惯。操作文件时候记得添加 defer 关闭文件资源代码
	defer dest_open.Close()
	//进行数据拷贝
	_, copy_err := io.Copy(dest_open, source_open)
	if copy_err != nil {
		log.Println(copy_err.Error())
		return false
	} else {
		return true
	}
}

//遍历文件夹获取文件夹下的文件夹
func GetDirectories(path string)([]string){
	var li []string
	rd,_ := ioutil.ReadDir(path)
	for _, fi := range rd{
		if fi.IsDir(){
			li = append(li,path+"\\"+fi.Name())
		}
	}
	return li
}

//遍历文件夹获取文件夹下的文件
func Get_files_in_dir(path string)([]string){
	var li []string
	rd,_ := ioutil.ReadDir(path)
	for _, fi := range rd{
		if fi.IsDir(){
			
		}else{
			li = append(li,path+"\\"+fi.Name())
		}
	}
	return li
}

func Get_substr_by_regexp(input,regexp_txt string)([]string){
	var result []string
	regexp_str := regexp.MustCompile(regexp_txt)
	if (regexp_str!= nil){
		sub_list := regexp_str.FindAllStringSubmatch(input,-1)
		for _,value := range sub_list{
			if(len(value)==2){
				result = append(result,value[1])
			}
		}
	}
	return result
}