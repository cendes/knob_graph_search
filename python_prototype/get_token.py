import re
import check_expression
import parse_func_call
import parse_struct

IS_NOT_RETURN = -1
IS_FUNC_RETURN = -2


def find_func_name(var_ref):
    args_start_indices = [m.start() for m in re.finditer("\\(", var_ref)]
    for args_start_index in args_start_indices:
        func_name = get_func_name(var_ref, args_start_index)
        if func_name is not None:
            return func_name
    return None


def get_func_name(var_ref, args_start_index):
    func_name_start = args_start_index - 1
    while (check_expression.is_valid_varname_char(var_ref[func_name_start]) or var_ref[func_name_start] == "*" or
           var_ref[func_name_start] == "." or var_ref[func_name_start] == ">"):
        if var_ref[func_name_start] == ">" and func_name_start > 0 and var_ref[func_name_start - 1] == "-":
            func_name_start -= 2
        else:
            func_name_start -= 1
    func_name = var_ref[func_name_start + 1:args_start_index]
    if func_name == "" or func_name in check_expression.C_KEYWORDS or "*" in func_name or "." in func_name or "->" in func_name:  # Ignore function pointers for now
        return None
    else:
        return func_name


def get_func_ptr_name(func_ptr_declaration):
    parenthesis_index = func_ptr_declaration.find("(")
    start_index = parenthesis_index + 1
    end_index = start_index
    while check_expression.is_valid_varname(func_ptr_declaration[end_index]) or func_ptr_declaration[end_index] == "*":
        end_index += 1

    arg_name = func_ptr_declaration[start_index:end_index]
    while arg_name[0] == "*":
        arg_name = arg_name[1:]

    return arg_name


def get_return_match_index(var_ref, var_ref_arr, var_name, struct_hierarchy, func_name):
    is_define = False
    if func_name in parse_func_call.visited_func_decls:
        func_declaration = parse_func_call.visited_func_decls[func_name]
        func_declaration_arr = func_declaration.split()
        if check_expression.is_var_declaration(func_name, var_ref) and func_declaration_arr[0] != var_ref_arr[0]:
            var_ref = func_declaration
            var_ref_arr = func_declaration_arr
        if "#define" in func_declaration_arr:
            is_define = True
            if "\\" in func_declaration_arr[-1]:
                return IS_NOT_RETURN
            if int(func_declaration_arr[2]) == int(var_ref_arr[2]):
                args_start = var_ref.find("(")
                statement_start = check_expression.recur_with_parenthesis(var_ref, args_start + 1, "(")
            else:
                statement_start = 0

    if not is_define:
        return_index = var_ref.find("return")
        if return_index < 0 or not check_expression.is_token_match(var_ref, return_index, len("return")):
            return IS_NOT_RETURN

        statement_start = return_index + len("return")

    if check_expression.is_func(var_ref[statement_start + 1:]):
        return IS_FUNC_RETURN

    var_indices = [m.start() for m in re.finditer(var_name, var_ref)]
    var_indices = [x for x in var_indices if x > statement_start]
    for var_index in var_indices:
        if check_expression.is_token_match(var_ref, var_index, len(var_name)):
            hierarchy_matches = parse_struct.get_struct_matches(var_ref, var_name, struct_hierarchy)
            if len(hierarchy_matches) == 0:
                return IS_NOT_RETURN
            return max(hierarchy_matches)

    return IS_NOT_RETURN


def get_eq_index(var_ref):
    eq_indices = [m.start() for m in re.finditer("=", var_ref)]
    for eq_index in eq_indices:
        if check_expression.is_assignment_op(var_ref, eq_index):
            return eq_index

    return None
