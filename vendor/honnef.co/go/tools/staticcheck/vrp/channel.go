package vrp

import (
	"fmt"

	"honnef.co/go/tools/ssa"
)

type ClassInterval struct {
	Size IntInterval
}

func (c ClassInterval) Union(other Range) Range {
	i, ok := other.(ClassInterval)
	if !ok {
		i = ClassInterval{EmptyIntInterval}
	}
	if c.Size.Empty() || !c.Size.IsKnown() {
		return i
	}
	if i.Size.Empty() || !i.Size.IsKnown() {
		return c
	}
	return ClassInterval{
		Size: c.Size.Union(i.Size).(IntInterval),
	}
}

func (c ClassInterval) String() string {
	return c.Size.String()
}

func (c ClassInterval) IsKnown() bool {
	return c.Size.IsKnown()
}

type MakeClassConstraint struct {
	aConstraint
	Buffer ssa.Value
}
type ClassChangeTypeConstraint struct {
	aConstraint
	X ssa.Value
}

func NewMakeClassConstraint(buffer, y ssa.Value) Constraint {
	return &MakeClassConstraint{NewConstraint(y), buffer}
}
func NewClassChangeTypeConstraint(x, y ssa.Value) Constraint {
	return &ClassChangeTypeConstraint{NewConstraint(y), x}
}

func (c *MakeClassConstraint) Operands() []ssa.Value       { return []ssa.Value{c.Buffer} }
func (c *ClassChangeTypeConstraint) Operands() []ssa.Value { return []ssa.Value{c.X} }

func (c *MakeClassConstraint) String() string {
	return fmt.Sprintf("%s = make(chan, %s)", c.Y().Name(), c.Buffer.Name())
}
func (c *ClassChangeTypeConstraint) String() string {
	return fmt.Sprintf("%s = changetype(%s)", c.Y().Name(), c.X.Name())
}

func (c *MakeClassConstraint) Eval(g *Graph) Range {
	i, ok := g.Range(c.Buffer).(IntInterval)
	if !ok {
		return ClassInterval{NewIntInterval(NewZ(0), PInfinity)}
	}
	if i.Lower.Sign() == -1 {
		i.Lower = NewZ(0)
	}
	return ClassInterval{i}
}
func (c *ClassChangeTypeConstraint) Eval(g *Graph) Range { return g.Range(c.X) }
