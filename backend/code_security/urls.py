from rest_framework.routers import DefaultRouter
from .views import CodeRepositoryViewSet, CodeFindingViewSet

router = DefaultRouter()
router.register(r"code-repositories", CodeRepositoryViewSet, basename="code-repositories")
router.register(r"code-findings", CodeFindingViewSet, basename="code-findings")

urlpatterns = router.urls
