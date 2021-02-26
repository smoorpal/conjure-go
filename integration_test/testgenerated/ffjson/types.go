package ffjson

type MyStruct struct {
	StringField string `json:"fieldname"`
	IntField    int
	Slice       []InnerStruct
}

type InnerStruct struct {
	Type string
}
