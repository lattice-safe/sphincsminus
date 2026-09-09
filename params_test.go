package sphincsminus

import "testing"

func TestParamsDerivedSizes(t *testing.T) {
	cases := []struct {
		p         *Params
		sigBytes  int
		htStart   int
		layerSize int
	}{
		// SPEC §2 table plus C13's explicitly spelled-out derived
		// quantities.
		{C7, 3704, 0, 0},
		{C9, 3816, 0, 0},
		{C10, 4008, 0, 0},
		{C11, 3976, 0, 0},
		{C13, 3688, 1952, 868},
	}

	for _, c := range cases {
		if got := c.p.SigBytes(); got != c.sigBytes {
			t.Errorf("%s: SigBytes() = %d, want %d", c.p.Name, got, c.sigBytes)
		}
		if c.htStart != 0 {
			if got := c.p.HTStart(); got != c.htStart {
				t.Errorf("%s: HTStart() = %d, want %d", c.p.Name, got, c.htStart)
			}
		}
		if c.layerSize != 0 {
			if got := c.p.LayerSize(); got != c.layerSize {
				t.Errorf("%s: LayerSize() = %d, want %d", c.p.Name, got, c.layerSize)
			}
		}
	}
}

func TestParamsValidate(t *testing.T) {
	for _, p := range AllParams {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: Validate() = %v, want nil", p.Name, err)
		}
	}
}

func TestParamsInvariant(t *testing.T) {
	for _, p := range AllParams {
		if p.K*p.A+p.H > 256 {
			t.Errorf("%s: k*a+h = %d exceeds 256", p.Name, p.K*p.A+p.H)
		}
		if p.H%p.D != 0 {
			t.Errorf("%s: h=%d not divisible by d=%d", p.Name, p.H, p.D)
		}
	}
}

func TestParamsByName(t *testing.T) {
	for _, p := range AllParams {
		got, ok := ParamsByName(p.Name)
		if !ok || got != p {
			t.Errorf("ParamsByName(%q) = %v, %v; want %v, true", p.Name, got, ok, p)
		}
	}
	if _, ok := ParamsByName("nope"); ok {
		t.Errorf("ParamsByName(%q) unexpectedly found", "nope")
	}
}

func TestParamsValidateRejectsBadShapes(t *testing.T) {
	bad := *C13
	bad.W = 16
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate() with w=16 should fail")
	}

	bad = *C13
	bad.L = 42
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate() with l=42 should fail")
	}

	bad = *C13
	bad.H = 23 // not a multiple of D=2
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate() with h not multiple of d should fail")
	}

	bad = *C13
	bad.K = 100 // k*a+h way over 256
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate() with k*a+h>256 should fail")
	}

	bad = *C13
	bad.D = 0
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate() with d=0 should fail")
	}

	bad = *C13
	bad.D = -1
	if err := bad.Validate(); err == nil {
		t.Errorf("Validate() with d=-1 should fail")
	}

	if err := (*Params)(nil).Validate(); err == nil {
		t.Errorf("Validate() on a nil *Params should fail")
	}
}
