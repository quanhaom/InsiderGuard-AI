from app.modules.collector.dispatcher import EventDispatcher
from app.schemas.collector import CollectorEvent


class CollectorService:

    @staticmethod
    def ingest(event: CollectorEvent):
        return EventDispatcher.dispatch(event)