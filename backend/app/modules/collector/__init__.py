from app.modules.parsers.parser_4624 import Parser4624
from app.modules.parsers.parser_4625 import Parser4625
from app.modules.parsers.registry import ParserRegistry


ParserRegistry.register(
    Parser4624()
)

ParserRegistry.register(
    Parser4625()
)