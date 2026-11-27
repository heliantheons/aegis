package provision

import (
	"context"

	"github.com/heliantheon/aegis/internal/cache"
	"github.com/heliantheon/aegis/models"
)

// Service 提供应用、服务、关系及连接配置的业务查询，内部通过缓存代理访问 Hermes。
type Service struct {
	cache *cache.Manager
}

// NewService 创建配置查询服务。
func NewService(cache *cache.Manager) *Service {
	return &Service{cache: cache}
}

func (s *Service) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	app, err := s.cache.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}
	return &app.Application, nil
}

func (s *Service) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	svc, err := s.cache.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	return &svc.Service, nil
}

func (s *Service) GetAppServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	return s.cache.GetAppServiceRelations(ctx, appID)
}

func (s *Service) ListDomainIDPConfigs(ctx context.Context, domainID string) ([]*models.DomainIDPConfig, error) {
	return s.cache.ListDomainIDPConfigs(ctx, domainID)
}

func (s *Service) ListApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error) {
	return s.cache.ListApplicationIDPConfigs(ctx, appID)
}
