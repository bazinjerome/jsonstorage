package jsonstorage

import (
	"testing"
)

func TestErrorRead(t *testing.T) {
	storage := &JsonStorage{
		"test1.txt",
		"password",
		"saltsaltsaltsaltsaltsaltsaltsalt",
		"saltsaltsaltsaltsaltsaltsaltsalt",
	}

	result,error := storage.getString("pouet")

	if result != "" {
		printErrorAndFail(t,"NO EXXISTING VALUE INSIDE STORAGE")
	}

	if error == nil {
		printErrorAndFail(t,"AN ERROR SHOULD OCCURED WHEN A KEY DOES NOT EXIST")
	}

}

func TestWrite(t *testing.T) {
	storage := &JsonStorage{
		"test2.txt",
		"password",
		"saltsaltsaltsaltsaltsaltsaltsalt",
		"saltsaltsaltsaltsaltsaltsaltsalt",
	}

	//an error might get returned here
	error := storage.storeString("pouetpouet", "camion")

	if error != nil {
		printErrorAndFail(t,"NO ERROR SHOULD OCCURED")
	}
}

func TestReadWrite(t *testing.T) {
	storage := &JsonStorage{
		"test3.txt",
		"password",
		"saltsaltsaltsaltsaltsaltsaltsalt",
		"saltsaltsaltsaltsaltsaltsaltsalt",
	}

	storage.storeString("pouetpouet", "camion")

	result,error  := storage.getString("pouetpouet")

	if error != nil {
		printErrorAndFail(t,"No Storage Error Should occured")
	}

	if result == "" {
		printErrorAndFail(t,"could not even retrieve something form storage")
	}

	if result != "camion" {
		printErrorAndFail(t,"result from Storage different than expected")
	}
}

func printErrorAndFail(t *testing.T, strError string){
	t.Error(strError)
	t.FailNow()
}