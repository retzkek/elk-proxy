package main

import (
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("You know, for search\n"))
}

func main() {
	http.HandleFunc("/", handler)
	log.Printf("About to listen on 9200. Go to http://127.0.0.1:9200/")
	err := http.ListenAndServe("127.0.0.1:9200", nil)
	if err != nil {
		log.Fatal(err)
	}
}
