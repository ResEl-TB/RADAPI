"""This module provides tools to work with Round-Robin pools of servers"""

from .autoldap import RoundRobinLdap
from .exceptions import NotFoundException, NoMoreIPException, ReadOnlyException
