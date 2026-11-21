//go:build js && wasm

// Browser build: boecheckScan(text) returns JSON with results and the Body of Evidence.
package main

import (
	"encoding/json"
	"strings"
	"syscall/js"

	"github.com/gerardrecinto/boecheck/internal/boe"
)

func main() {
	js.Global().Set("boecheckScan", js.FuncOf(func(_ js.Value, args []js.Value) any {
		text := args[0].String()
		name := "input.yaml"
		if strings.Contains(text, "resource \"") {
			name = "input.tf"
		}
		rs, err := boe.Scan([]boe.File{{Name: name, Data: []byte(text)}}, boe.Options{})
		if err != nil {
			b, _ := json.Marshal(map[string]string{"error": err.Error()})
			return string(b)
		}
		if rs == nil {
			rs = []boe.Result{}
		}
		b, _ := json.Marshal(map[string]any{"results": rs, "boe": boe.BoE("browser input", rs), "text": boe.Text(rs, false)})
		return string(b)
	}))
	select {}
}
