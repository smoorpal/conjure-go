package visitors

import (
	"unsafe"

	"github.com/palantir/conjure-go-runtime/v2/conjure-go-contract/errors"
	"github.com/palantir/pkg/binary"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/pkg/safelong"
	"github.com/palantir/pkg/uuid"
	"github.com/tidwall/gjson"
)

type Foo struct {
	FieldAny                 interface{}
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
		case "fieldAny":
			if value.Type != gjson.JSON && value.Type != gjson.String && value.Type != gjson.Number && value.Type != gjson.True && value.Type != gjson.False {
				err = errors.NewInvalidArgument()
				return false
			}
			x.FieldAny = value.Value()
		case "fieldString":
			if value.Type != gjson.String {
				err = errors.NewInvalidArgument()
				return false
			}
			x.FieldString = value.Str
		case "fieldInt":
			if value.Type != gjson.Number {
				err = errors.NewInvalidArgument()
				return false
			}
			x.FieldInt = int(value.Int())
		case "fieldDatetime":
			if value.Type != gjson.String {
				err = errors.NewInvalidArgument()
				return false
			}
			err = x.FieldDatetime.UnmarshalText([]byte(value.Str))
		case "fieldSafelong":
			if value.Type != gjson.Number {
				err = errors.NewInvalidArgument()
				return false
			}
			err = x.FieldSafelong.UnmarshalJSON([]byte(value.Raw))
		case "fieldUUID":
			if value.Type != gjson.String {
				err = errors.NewInvalidArgument()
				return false
			}
			err = x.FieldUUID.UnmarshalText([]byte(value.Str))
		case "fieldBinary":
			if value.Type != gjson.String {
				err = errors.NewInvalidArgument()
				return false
			}
			x.FieldBinary, err = binary.Binary(value.Str).Bytes()
		case "fieldOptionalString":
			if value.Type == gjson.Null {
				if value.Type != gjson.String {
					err = errors.NewInvalidArgument()
					return false
				}
				v = value.Str
				x.FieldOptionalString = &v
			}
		case "fieldListString":
			if value.IsArray() {
				value.ForEach(func(_, value gjson.Result) bool {
					var v string
					if value.Type != gjson.String {
						err = errors.NewInvalidArgument()
						return false
					}
					v = value.Str
					x.FieldListString = append(x.FieldListString, v)
					return err == nil
				})
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldListInteger":
			if value.IsArray() {
				value.ForEach(func(_, value gjson.Result) bool {
					var v int
					if value.Type != gjson.Number {
						err = errors.NewInvalidArgument()
						return false
					}
					v = int(value.Int())
					x.FieldListInteger = append(x.FieldListInteger, v)
					return err == nil
				})
			} else {
				err = errors.NewInvalidArgument()
			}
		case "fieldListDatetime":
			if value.IsArray() {
				value.ForEach(func(_, value gjson.Result) bool {
					var v datetime.DateTime
					if value.Type != gjson.String {
						err = errors.NewInvalidArgument()
						return false
					}
					err = v.UnmarshalText([]byte(value.Str))
					x.FieldListDatetime = append(x.FieldListDatetime, v)
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
					if value.Type != gjson.String {
						err = errors.NewInvalidArgument()
						return false
					}
					destKey = value.Str
					var destVal string
					if value.Type != gjson.String {
						err = errors.NewInvalidArgument()
						return false
					}
					destVal = value.Str
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
					if value.Type != gjson.String {
						err = errors.NewInvalidArgument()
						return false
					}
					err = destKey.UnmarshalText([]byte(value.Str))
					var destVal safelong.SafeLong
					if value.Type != gjson.Number {
						err = errors.NewInvalidArgument()
						return false
					}
					err = destVal.UnmarshalJSON([]byte(value.Raw))
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
