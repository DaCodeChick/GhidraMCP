from .addresses import register_address_tools
from .arrays import register_array_tools
#from .bsim import register_bsim_tools
from .categories import register_category_tools
from .classes import register_class_tools
from .comments import register_comment_tools
from .data import register_data_tools
from .enums import register_enum_tools
from .functions import register_function_tools
from .globals import register_global_tools
from .labels import register_label_tools
from .misc import register_misc_tools
from .namespaces import register_namespace_tools
from .strings import register_string_tools
from .structs import register_struct_tools
from .types import register_type_tools
from .variables import register_variable_tools
from .xrefs import register_xref_tools

def register_all_tools():
	register_address_tools()
	register_array_tools()
	#register_bsim_tools()
	register_category_tools()
	register_class_tools()
	register_comment_tools()
	register_data_tools()
	register_enum_tools()
	register_function_tools()
	register_global_tools()
	register_label_tools()
	register_misc_tools()
	register_namespace_tools()
	register_string_tools()
	register_struct_tools()
	register_type_tools()
	register_variable_tools()
	register_xref_tools()

__all__ = [
	"register_all_tools"
]
