import os
import glob
import logging
import fnmatch

from pyparsing import ParseException
from gixy.core.exceptions import InvalidConfiguration
from gixy.parser import raw_parser
from gixy.directives import block, directive
from gixy.utils.text import to_native

LOG = logging.getLogger(__name__)


class NginxParser(object):
    def __init__(self, cwd="", allow_includes=True):
        self.cwd = cwd
        self.configs = {}
        self.is_dump = False
        self.allow_includes = allow_includes
        self.directives = {}
        self.parser = raw_parser.RawParser()
        self._init_directives()

    def parse_file(self, path, root=None):
        LOG.debug("Parse file: {0}".format(path))
        content = open(path).read()
        return self.parse(content=content, root=root, path_info=path)

    def parse(self, content, root=None, path_info=None):
        if not root:
            root = block.Root()
        try:
            parsed = self.parser.parse(content)
        except ParseException as e:
            error_msg = "char {char} (line:{line}, col:{col})".format(
                char=e.loc, line=e.lineno, col=e.col
            )
            if path_info:
                LOG.error(
                    'Failed to parse config "{file}": {error}'.format(
                        file=path_info, error=error_msg
                    )
                )
            else:
                LOG.error("Failed to parse config: {error}".format(error=error_msg))
            raise InvalidConfiguration(error_msg)

        if len(parsed) and parsed[0].getName() == "file_delimiter":
            #  Were parse nginx dump
            LOG.info("Switched to parse nginx configuration dump.")
            root_filename = self._prepare_dump(parsed)
            path_info = root_filename
            self.is_dump = True
            self.cwd = os.path.dirname(root_filename)
            parsed = self.configs[root_filename]

        self.parse_block(parsed, root, path_info)
        return root

    def parse_block(self, parsed_block, parent, path_info):
        for parsed in parsed_block:
            parsed_type = parsed.getName()
            line = parsed.get('line', None)
            parsed_name = parsed[0]
            parsed_info = {parsed_name: line}
            parsed_args = parsed[1:]
            if parsed_type == "include":
                # TODO: WTF?!
                self._resolve_include(parsed_args, parent, path_info)
            else:
                directive_inst = self.directive_factory(
                    parsed_type, parsed_info, parsed_args, path_info
                )
                if directive_inst:
                    parent.append(directive_inst)

    def directive_factory(self, parsed_type, parsed_info, parsed_args, path_info):
        klass = self._get_directive_class(parsed_type, parsed_info, path_info)
        if not klass:
            return None

        parsed_name = list(parsed_info.keys())[0]
        if klass.is_block:
            args = [to_native(v).strip() for v in parsed_args[0]]
            children = parsed_args[1]

            inst = klass(parsed_name, args)
            self.parse_block(children, inst, path_info)
            return inst
        else:
            args = [to_native(v).strip() for v in parsed_args]
            return klass(parsed_name, args)

    def _get_directive_class(self, parsed_type, parsed_info, path_info):
        parsed_name = list(parsed_info.keys())[0]
        parsed_line = parsed_info.get(parsed_name, '<unknown>')
        if (
            parsed_type in self.directives
            and parsed_name in self.directives[parsed_type]
        ):
            return self.directives[parsed_type][parsed_name]
        elif parsed_type == "block":
            return block.Block
        elif parsed_type == "directive":
            return directive.Directive
        elif parsed_type == "unparsed_block":
            LOG.warning('Skip unparseable block in %s beginning at line %s: "%s"', path_info, parsed_line, parsed_name)
            return None
        else:
            return None

    def _init_directives(self):
        self.directives["block"] = block.get_overrides()
        self.directives["directive"] = directive.get_overrides()

    def _resolve_include(self, args, parent, path_info):
        pattern = args[0]
        #  TODO(buglloc): maybe file providers?
        if self.is_dump:
            return self._resolve_dump_include(pattern=pattern, parent=parent, path_info=path_info)
        if not self.allow_includes:
            LOG.debug("Includes are disallowed in %s, skip: %s", path_info, pattern)
            return

        return self._resolve_file_include(pattern=pattern, parent=parent, path_info=path_info)

    def _resolve_file_include(self, pattern, parent, path_info):
        path = os.path.join(self.cwd, pattern)
        exists = False
        for file_path in glob.iglob(path):
            if not os.path.exists(file_path):
                LOG.warning("Included file '%s' not found from '%s'", file_path, path_info)
                continue
            exists = True
            # parse the include into current context
            self.parse_file(file_path, parent)

        if not exists:
            LOG.warning("Included file '%s' not found from '%s'", path, path_info)

    def _resolve_dump_include(self, pattern, parent, path_info):
        path = os.path.join(self.cwd, pattern)
        founded = False
        for file_path, parsed in self.configs.items():
            if fnmatch.fnmatch(file_path, path):
                founded = True
                include = block.IncludeBlock("include", [file_path])
                parent.append(include)
                self.parse_block(parsed, include, file_path)

        if not founded:
            LOG.warning("Included file '%s' not found from '%s'", path, path_info)

    def _prepare_dump(self, parsed_block):
        filename = ""
        root_filename = ""
        for parsed in parsed_block:
            if parsed.getName() == "file_delimiter":
                if not filename:
                    root_filename = parsed[0]
                filename = parsed[0]
                self.configs[filename] = []
                continue
            self.configs[filename].append(parsed)
        return root_filename
