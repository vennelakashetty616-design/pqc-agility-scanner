package main

import (
	"fmt"

	"example.com/legacy-billing/internal"
)

func main() {
	sum := internal.Fingerprint([]byte("demo"))
	fmt.Println(sum)
}
