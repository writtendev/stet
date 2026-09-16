package attest

import "testing"

func TestVerify_LeafNotV3(t *testing.T) {
	sc := baseScenario()
	st, trust := sc.build(t)

	stmt, err := decodePackedAttStmt(st.AttStmt)
	if err != nil {
		t.Fatal(err)
	}
	patchedLeaf := forceCertVersion(t, stmt.X5C[0], 0) // re-encode the version INTEGER as v1
	newX5C := append([][]byte{patchedLeaf}, stmt.X5C[1:]...)
	st.AttStmt = marshalTestAttStmt(t, stmt.Alg, stmt.Sig, newX5C, stmt.ECDAAKeyID)

	res, err := verify(st, Options{At: sc.verifyAt}, trust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Verified {
		t.Fatalf("expected Verified=false, got true")
	}
	if len(res.Reasons) != 1 || res.Reasons[0] != reasonLeafNotV3 {
		t.Errorf("expected reasons=[%s], got %v", reasonLeafNotV3, res.Reasons)
	}
}
