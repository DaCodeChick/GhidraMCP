#from .bsim import register_bsim_tools
from .comment import register_comment_tools
from .create import register_create_tools
from .datatype import register_datatype_tools
from .decompile import register_decompile_tools
from .get import register_get_tools
from .list import register_list_tools
from .misc import register_misc_tools
from .rename import register_rename_tools
from .search import register_search_tools
from .set import register_set_tools

__all__ = [
	# "register_bsim_tools",
	"register_comment_tools",
	"register_create_tools",
	"register_datatype_tools",
	"register_decompile_tools",
	"register_get_tools",
	"register_list_tools",
	"register_misc_tools",
	"register_rename_tools",
	"register_search_tools",
	"register_set_tools"
]

def register_all_tools(mcp):
	"""Register all tools with the given MCP instance."""

	#register_bsim_tools(mcp)
	register_comment_tools(mcp)
	register_create_tools(mcp)
	register_datatype_tools(mcp)
	register_decompile_tools(mcp)
	register_get_tools(mcp)
	register_list_tools(mcp)
	register_misc_tools(mcp)
	register_rename_tools(mcp)
	register_search_tools(mcp)
	register_set_tools(mcp)
