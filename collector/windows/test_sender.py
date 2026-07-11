from app.collector import WindowsCollector
from app.normalizer import Normalizer
from app.sender import Sender

collector = WindowsCollector()

for raw_event in collector.collect():

    event = Normalizer.normalize(
        raw_event
    )

    print(
        Sender.send(event)
    )

    break