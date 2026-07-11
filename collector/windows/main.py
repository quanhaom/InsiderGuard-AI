from app.service import CollectorService


def main() -> None:
    service = CollectorService()
    service.run()


if __name__ == "__main__":
    main()