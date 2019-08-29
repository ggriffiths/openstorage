package auth

import (
	"context"
	"testing"
)

func TestSelfSignedAuthorize(t *testing.T) {
	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH3Mtkx/k9nY260RwgGr9AEE6ZyX
v7GnCsMuq4gA/8ns4fDMT2KgkDBQ22YJVsVEOqeXokcEr7ANgdG4Y6Ixo+WnatWT
OsjaOeAuFkbFeT7n5Ar1JTRY95+Ezw5UlzcjVSvPNid2ruv64val9T+KnJMK3emt
HxvnubOU80vwmsLjAgMBAAE=
-----END PUBLIC KEY-----`)

	// This was used to generate the below token. Saving
	// here to future use to add more test tokens.
	privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgH3Mtkx/k9nY260RwgGr9AEE6ZyXv7GnCsMuq4gA/8ns4fDMT2Kg
kDBQ22YJVsVEOqeXokcEr7ANgdG4Y6Ixo+WnatWTOsjaOeAuFkbFeT7n5Ar1JTRY
95+Ezw5UlzcjVSvPNid2ruv64val9T+KnJMK3emtHxvnubOU80vwmsLjAgMBAAEC
gYACRk5RickBmmM2eOi6IQLTdeRHeZL0wmF2cASX+/SkEQ1wzjDtRpv007Fz4d1Y
ycgJubssb5BBrazYPu5GQ4GEIdlwqrx1B6sf5UuUIbVzaZWn1jkB1jai5ctL6NFt
qcuxlvpb3I812HUHE7v7lq+d6B3yTRln1MZ9nNpKqQQoGQJBAOSpHb6KxzwI2FYW
v5DFotqmn+ROlHQGp/4ks6dVdL0Z663JflEmRoJ7L67Gio3ZWkgKXAE6+Ji5LJwN
k4TJ0McCQQCM1zW9i4wRhSl0TdsuT49MTpwhuQPeykXacdFBKsF8nzDc8+66JkN2
fQyUcSz1KDKNtrsHVjgCPZS5Z3Ikx9kFAkEA44NBjS0YP6utVTsdMDb1awkPXmKx
YyCcVkq+Vmi41s7LqQcrICMtVPas4wG5KppxMezcznyWjZ7xu/PmK+GCUQJBAIuQ
a6mj0i4+ZcDhsfPnVRoJwABO5f3tNWFtbi4En23OFk6tzwBaEHonGsMyj5l0tvvl
etqfXqshuPItB1hZTb0CQAvJkxGSN8d5Ejruu2M7hfGFHLjTCgUe2MtpQMwRWEmF
59dT36YhiMLzooB214PGZQ2gnEFOoukIrmGslzbIajA=
-----END RSA PRIVATE KEY-----
`
	_ = privateKey

	// has "exp" and "iat" values as strings
	jwta, err := NewJwtAuth(&JwtAuthConfig{
		RsaPublicPem: publicKey,
	})
	if err != nil {
		t.Fatalf("Failed to create new jet auth %v", err)
	}

	tt := []struct {
		testName    string
		token       string
		expectError bool
	}{
		{
			testName:    "expired exp and iat as strings should not authenticate",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cHMiOlsiKiJdLCJzdWIiOiJqc3RldmVucyIsInJvbGVzIjpbInN5c3RlbS5hZG1pbiJdLCJpc3MiOiJqc3RldmVucyIsImV4cCI6IjE1NjU4ODc2NzYiLCJpYXQiOiIxNTY1ODg0MDc2IiwiZW1haWwiOiJvcGVuc3RvcmFnZS5pbyIsIm5hbWUiOiJKaW0gU3RldmVucyJ9.QdhIwf7z6iNZ31OhVWUQIwBi0_LueG_Jbudf5TudpGlXDBCNkLIkkd-NL0T_zI3k-HePBr7PWkdQNaOMEbat_Rt9JfL00fiZck2gD9JwsvL8VJoKN19XjBpq9pH2naUR4KsPydpl8BQG22S6arRUjSIkzTqVsAsHOcq0J-MBVWQ",
			expectError: true,
		},
		{
			testName:    "expired exp and iat as numbers should not authenticate",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cHMiOlsiKiJdLCJzdWIiOiJqc3RldmVucyIsInJvbGVzIjpbInN5c3RlbS5hZG1pbiJdLCJpc3MiOiJqc3RldmVucyIsImV4cCI6MTU2NTg4NzY3NiwiaWF0IjoxNTY1ODg0MDc2LCJlbWFpbCI6Im9wZW5zdG9yYWdlLmlvIiwibmFtZSI6IkppbSBTdGV2ZW5zIn0.fMv1Hj4QyW3XQ_bC1uOT3nyJ9EQt0ohIwG7yN9FY2O6HZnWM5D68_whysXSt960h7jFJKEc2l-XitvK8IFE8CrgBBBZ-4YBCV5gbvEpI9eNpeTOT5m1RkAE3f-QgqrHSylp6l9eOTXWz-OYg1E474TOMw3mQc1QJ3xn7shFTCko",
			expectError: true,
		},
		{
			testName:    "non-existent exp and iat should not authenticate",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cHMiOlsiKiJdLCJzdWIiOiJqc3RldmVucyIsInJvbGVzIjpbInN5c3RlbS5hZG1pbiJdLCJpc3MiOiJqc3RldmVucyIsImVtYWlsIjoib3BlbnN0b3JhZ2UuaW8iLCJuYW1lIjoiSmltIFN0ZXZlbnMifQ.Tx7c6zQzbuQqmDsfU6Ml0m0xN_QxDbzu3XRwelLmwxhI4SBCeiSaYsE4XzLp9ZdAfK3kBYVc-6zIaXrusc_2Tm5P-cQplBbytWlragiclNhJ1-BVOznvcflC_qBLTNKsLkXFRXqNunFSEozzCmo16yzb_HGceYWAqc2NoHOX1y8",
			expectError: false,
		},
	}

	for _, tc := range tt {
		_, err = jwta.AuthenticateToken(context.Background(), tc.token)
		if tc.expectError {
			if err == nil {
				t.Fatalf("[%s] Expected authentication error, but got nil", tc.testName)
			}
		} else {
			if err != nil {
				t.Fatalf("[%s] Expected no error, but got %s", tc.testName, err.Error())
			}
		}
	}
}
