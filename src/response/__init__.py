"""Controlled defensive response (Part 7).

Detection and response are deliberately separate: this package never
performs a real firewall/network modification. The default mode is
DRY_RUN, which only simulates and logs what a response WOULD do.
"""
