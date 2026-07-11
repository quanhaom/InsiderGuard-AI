from app.schemas.collector import CollectorEvent


class EventDispatcher:

    @staticmethod
    def dispatch(event: CollectorEvent):
        raise NotImplementedError