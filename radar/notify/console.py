import logging


class ConsoleChannel:
    def send(self, message):
        logging.getLogger("radar").warning(message)
        return True
