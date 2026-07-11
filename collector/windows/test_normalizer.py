from app.collector import WindowsCollector
from app.normalizer import Normalizer

collector = WindowsCollector()

for raw_event in collector.collect():

    event = Normalizer.normalize(
        raw_event
    )

    print("=" * 80)

    print(event)

    break