package authorize

import (
	"testing"

	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
)

func TestRequiredIdentityTypesFollowAudienceShape(t *testing.T) {
	t.Parallel()

	staff := `["staff"]`
	staffAndPasskey := `["staff","passkey"]`

	tests := []struct {
		name string
		flow *types.AuthFlow
		want []string
	}{
		{
			name: "single audience",
			flow: &types.AuthFlow{
				Request: &types.AuthRequest{Audience: "iris"},
				Service: &models.Service{ServiceID: "iris", RequiredIdentities: &staff},
			},
			want: []string{"staff"},
		},
		{
			name: "multi audience union",
			flow: &types.AuthFlow{
				Request: &types.AuthRequest{Audiences: map[string]*types.RequestAudienceScope{
					"hermes": {},
					"iris":   {},
				}},
				Services: []models.Service{
					{ServiceID: "hermes", RequiredIdentities: &staffAndPasskey},
					{ServiceID: "iris", RequiredIdentities: &staff},
				},
			},
			want: []string{"passkey", "staff"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := requiredIdentityTypes(test.flow)
			if len(got) != len(test.want) {
				t.Fatalf("requiredIdentityTypes() = %v, want %v", got, test.want)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Fatalf("requiredIdentityTypes() = %v, want %v", got, test.want)
				}
			}
		})
	}
}
