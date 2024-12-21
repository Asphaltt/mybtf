package mybtf

import "github.com/cilium/ebpf/btf"

func IsChar(t btf.Type) bool {
	t = UnderlyingType(t)
	i, ok := t.(*btf.Int)
	return ok && i.Size == 1 && i.Encoding&btf.Signed == btf.Signed && i.Name == "char"
}

func IsInt(typ btf.Type) bool {
	i, ok := typ.(*btf.Int)
	return ok && i.Name == "int"
}

func IsBool(typ btf.Type) bool {
	def, ok := typ.(*btf.Typedef)
	return ok && def.Name == "bool"
}

func IsVoid(t btf.Type) bool {
	_, ok := t.(*btf.Void)
	return ok
}

func IsVoidPointer(t btf.Type) bool {
	p, ok := t.(*btf.Pointer)
	return ok && IsVoid(p.Target)
}

func IsStructPointer(t btf.Type, structName string) bool {
	p, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}

	s, ok := p.Target.(*btf.Struct)
	return ok && s.Name == structName
}

func UnderlyingType(t btf.Type) btf.Type {
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
		case *btf.Volatile:
			t = v.Type
		case *btf.Const:
			t = v.Type
		case *btf.Restrict:
			t = v.Type
		default:
			return t
		}
	}
}

func HaveEnumValue(spec *btf.Spec, enumName, enumValue string) bool {
	types, err := spec.AnyTypesByName(enumName)
	if err != nil {
		return false
	}

	for _, t := range types {
		e, ok := t.(*btf.Enum)
		if !ok {
			continue
		}

		for _, v := range e.Values {
			if v.Name == enumValue {
				return true
			}
		}
	}

	return false
}
