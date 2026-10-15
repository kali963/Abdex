"""Imports every domain model so metadata (Alembic, create_all) sees all tables."""
from app.modules.accounts import models as accounts  # noqa: F401
from app.modules.documents import models as documents  # noqa: F401
from app.modules.fleet import models as fleet  # noqa: F401
from app.modules.orders import models as orders  # noqa: F401
from app.modules.bids import models as bids  # noqa: F401
from app.modules.deals import models as deals  # noqa: F401
from app.modules.platform import models as platform  # noqa: F401
from app.modules.chat import models as chat  # noqa: F401
from app.modules.notifications import models as notifications  # noqa: F401
from app.modules.billing import models as billing  # noqa: F401
from app.modules.rating import models as rating  # noqa: F401
from app.modules.webhooks import models as webhooks  # noqa: F401
