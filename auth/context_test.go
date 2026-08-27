package auth

import (
	"testing"

	"github.com/heliantheon/aegis/internal/types"
	"github.com/heliantheon/aegis/models"
)

func TestNewAuthContextResponseUsesApplicationDescription(t *testing.T) {
	t.Parallel()

	applicationDescription := "Heliantheon 平台统一管理入口。"
	serviceDescription := "菜谱管理、收藏与推荐服务"
	response := newAuthContextResponse(&types.AuthFlow{
		Application: &models.Application{
			DomainID:    "platform",
			AppID:       "atlas",
			Name:        "Atlas 管理控制台",
			Description: &applicationDescription,
		},
		Service: &models.Service{
			DomainID:    models.InheritedDomainID,
			ServiceID:   "zwei",
			Name:        "Zwei 菜谱服务",
			Description: &serviceDescription,
		},
	})

	if response.Application == nil || response.Application.Description == nil {
		t.Fatal("application description is missing")
	}
	if got := *response.Application.Description; got != applicationDescription {
		t.Fatalf("application description = %q, want %q", got, applicationDescription)
	}
	if response.Service == nil || response.Service.DomainID != "platform" {
		t.Fatalf("service domain = %v, want platform", response.Service)
	}
}
