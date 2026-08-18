package semver

import "testing"

func TestParseRejectsAnythingOutsideTheModel(t *testing.T) {
	for _, in := range []string{
		"", "1", "1.4", "1.4.2.3", "v1.4.2", "1.4.2-rc.1", "1.4.2+build", "01.4.2", "1.04.2",
		"1.4.2 ", " 1.4.2", "-1.4.2", "1.4.x", "1.4.2\n",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted an unsupported version", in)
		}
	}
}

func TestParseAndString(t *testing.T) {
	v, err := Parse("1.4.2")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if v.Major != 1 || v.Minor != 4 || v.Patch != 2 {
		t.Fatalf("got %+v", v)
	}
	if v.String() != "1.4.2" {
		t.Fatalf("String() = %q", v.String())
	}
}

func TestCompareOrdersByComponent(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.4.2", "1.4.2", 0},
		{"1.4.2", "1.4.3", -1},
		{"1.5.0", "1.4.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"9.9.9", "1.4.2", 1},
	}
	for _, c := range cases {
		if got := Compare(MustParse(c.a), MustParse(c.b)); got != c.want {
			t.Errorf("Compare(%s,%s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRangeSatisfaction(t *testing.T) {
	cases := []struct {
		spec, version string
		want          bool
	}{
		{"1.4.2", "1.4.2", true},
		{"1.4.2", "1.5.0", false},
		{"1.4.2", "1.4.1", false},
		{"^1.4.2", "1.4.2", true},
		{"^1.4.2", "1.5.0", true},
		{"^1.4.2", "1.4.1", false},
		{"^1.4.2", "2.0.0", false},
		{"^1.4.2", "9.9.9", false},
		{">=1.4.2", "1.4.2", true},
		{">=1.4.2", "1.5.0", true},
		{">=1.4.2", "9.9.9", true},
		{">=1.4.2", "1.4.1", false},
		{">=1.4.2", "0.9.9", false},
	}
	for _, c := range cases {
		r, err := ParseRange(c.spec)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", c.spec, err)
		}
		if got := r.Satisfies(MustParse(c.version)); got != c.want {
			t.Errorf("%q.Satisfies(%q) = %v, want %v", c.spec, c.version, got, c.want)
		}
	}
}

func TestParseRangeRejectsUnsupportedForms(t *testing.T) {
	for _, in := range []string{"", "~1.4.2", "*", "^", "^1.4", "1.x", "^^1.4.2", ">1.4.2", ">=", ">=1.4", "<=1.4.2", ">= 1.4.2"} {
		if _, err := ParseRange(in); err == nil {
			t.Errorf("ParseRange(%q) accepted an unsupported range", in)
		}
	}
}

func TestRangeString(t *testing.T) {
	for _, in := range []string{"1.4.2", "^1.4.2", ">=1.4.2"} {
		r, err := ParseRange(in)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", in, err)
		}
		if r.String() != in {
			t.Errorf("String() = %q, want %q", r.String(), in)
		}
	}
}
