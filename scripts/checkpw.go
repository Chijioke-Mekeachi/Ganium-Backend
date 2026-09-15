package main

import (
	"fmt"

	"ganium/src/utils"
)

func main() {
	hash := "$2a$10$rxmCXg/WnjrpXC1ybjTYN.vjBHxlR3qCex3tyYlwovb5L56GKobhG"
	ok := utils.CheckPassword("password123#", hash)
	fmt.Println("CheckPassword returned:", ok)
}
