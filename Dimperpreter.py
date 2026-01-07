class Dimperpreter:
    """
    Symbols:
    ,  -> next argument
    ;  -> end arguments
    @  -> escape / skip next character
    """

    def __init__(self, file_obj):
        # file_obj must be an open file (text mode)
        self.file = file_obj
        self.buffer = None  # single-character lookahead buffer

    def _read_char(self):
        """Read one character from file, using lookahead buffer if needed."""
        if self.buffer is not None:
            ch = self.buffer
            self.buffer = None
            return ch
        return self.file.read(1)

    def _unread_char(self, ch):
        """Push one character back (single-char lookahead)."""
        self.buffer = ch

    def Next(self):
        param = ""
        params = []

        while True:
            ch = self._read_char()
            if ch == "":
                # EOF
                if param:
                    params.append(param)
                break

            if ch == "@":
                # escape next character
                next_ch = self._read_char()
                if next_ch != "":
                    param += next_ch

            elif ch == ",":
                params.append(param)
                param = ""

            elif ch == ";":
                params.append(param)
                break

            else:
                param += ch

        return params

    def LeftRawData(self):
        """
        Returns remaining unread data as a generator (streamed),
        not loaded fully into memory.
        """
        if self.buffer is not None:
            yield self.buffer
            self.buffer = None

        while True:
            chunk = self.file.read(1024)
            if not chunk:
                break
            yield chunk
