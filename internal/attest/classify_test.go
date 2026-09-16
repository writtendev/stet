package attest

import "testing"

func TestVerify_Classification(t *testing.T) {
	tests := []struct {
		name      string
		uv        bool
		uvMethods []string
		want      Class
	}{
		{
			name:      "UV clear gives touch",
			uv:        false,
			uvMethods: []string{"presence_internal", "passcode_external"},
			want:      ClassHardwareTouch,
		},
		{
			name:      "UV set with a PIN-capable AAGUID gives PIN",
			uv:        true,
			uvMethods: []string{"presence_internal", "passcode_external"},
			want:      ClassHardwarePIN,
		},
		{
			name:      "UV set with a biometric-only AAGUID gives biometric",
			uv:        true,
			uvMethods: []string{"fingerprint_internal"},
			want:      ClassHardwareBiometric,
		},
		{
			name:      "UV set with a bio+PIN AAGUID gives PIN",
			uv:        true,
			uvMethods: []string{"fingerprint_internal", "passcode_external"},
			want:      ClassHardwarePIN,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := baseScenario()
			sc.uv = tc.uv
			sc.uvMethods = tc.uvMethods

			res, err := sc.verify(t)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Verified {
				t.Fatalf("expected Verified=true, reasons=%v", res.Reasons)
			}
			if res.Class != tc.want {
				t.Errorf("expected %v, got %v", tc.want, res.Class)
			}
		})
	}
}
