class NoMoreIPException(Exception):
    pass

class NotFoundException(Exception):
    pass

class UserNotFoundException(NotFoundException):
    pass

class MachineNotFoundException(NotFoundException):
    pass

class ReadOnlyException(Exception):
    pass
