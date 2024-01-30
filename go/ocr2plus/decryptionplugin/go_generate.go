//go:generate protoc -I. --go_out=.  types.proto
//go:generate protoc -I. --go_out=./config  ./config/config_types.proto
//go:generate protoc -I. --go_out=. ocr2_types.proto
//go:generate protoc -I. --go_out=. ocr3_types.proto

package decryptionplugin
