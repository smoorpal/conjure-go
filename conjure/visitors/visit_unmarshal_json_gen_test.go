package visitors

import (
	"unsafe"

	"github.com/palantir/conjure-go-runtime/v2/conjure-go-contract/errors"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/pkg/safelong"
	"github.com/palantir/pkg/uuid"
	"github.com/tidwall/gjson"
)

type Foo struct {
	FieldString              string
	FieldInt                 int
	FieldDatetime            datetime.DateTime
	FieldSafelong            safelong.SafeLong
	FieldUUID                uuid.UUID
	FieldBinary              []byte
	FieldOptionalString      *string
	FieldListString          []string
	FieldListInteger         []int
	FieldListDatetime        []datetime.DateTime
	FieldMapStringString     map[string]string
	FieldMapDatetimeSafelong map[datetime.DateTime]safelong.SafeLong
}

func (x *Foo) UnmarshalJSON(data []byte) error {
	str := *(*string)(unsafe.Pointer(&data))
	if !gjson.Valid(str) {
		return errors.NewInvalidArgument()
	}
	value := gjson.Parse(str)
	if !value.IsObject() {
		return errors.NewInvalidArgument()
	}
	var err error
	value.ForEach(func(key, value gjson.Result) bool {
		switch key.Str {
		case "fieldString":
			if value.Type == gjson.String {
				x.FieldString = value.Str
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldDatetime":
			if value.Type == gjson.String {
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldOptionalString":
			if value.Type != gjson.Null {
				if value.Type == gjson.String {
					v := value.Str
					x.FieldOptionalString = &v
				} else {
					err = errors.NewInvalidArgument()
				}
			}
		case "fieldListString":
			if value.IsArray() {
				value.ForEach(func(_, value gjson.Result) bool {
					if value.Type == gjson.String {
						v := value.Str
						x.FieldListString = append(x.FieldListString, v)
					} else {
						err = errors.NewInvalidArgument()
					}
					return err == nil
				})
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldListDatetime":
			if value.IsArray() {
				value.ForEach(func(_, value gjson.Result) bool {
					if value.Type == gjson.String {
						v, parseErr := datetime.ParseDateTime(value.Str)
						err = parseErr
						x.FieldListDatetime = append(x.FieldListDatetime, v)
					} else {
						err = errors.NewInvalidArgument()
					}
					return err == nil
				})
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldMapStringString":
			if value.IsObject() {
				if x.FieldMapStringString == nil {
					x.FieldMapStringString = make(map[string]string)
				}
				value.ForEach(func(key, value gjson.Result) bool {
					var destKey string
					if value.Type == gjson.String {
						destKey = value.Str
					} else {
						err = errors.NewInvalidArgument()
					}
					var destVal string
					if value.Type == gjson.String {
						destVal = value.Str
					} else {
						err = errors.NewInvalidArgument()
					}
					x.FieldMapStringString[destKey] = destVal
					return err == nil
				})
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldMapDatetimeSafelong":
			if value.IsObject() {
				if x.FieldMapDatetimeSafelong == nil {
					x.FieldMapDatetimeSafelong = make(map[datetime.DateTime]safelong.SafeLong)
				}
				value.ForEach(func(key, value gjson.Result) bool {
					var destKey datetime.DateTime
					if value.Type == gjson.String {
						destKey, err = datetime.ParseDateTime(value.Str)
					} else {
						err = errors.NewInvalidArgument()
					}
					var destVal safelong.SafeLong
					if value.Type == gjson.Number {
						destVal, err = safelong.NewSafeLong(value.Int())
					} else {
						err = errors.NewInvalidArgument()
					}
					x.FieldMapDatetimeSafelong[destKey] = destVal
					return err == nil
				})
			} else {
				err = errors.NewInvalidArgument()
			}
		}

		return err == nil
	})
	return err
}
