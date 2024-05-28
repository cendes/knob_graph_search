import re
import var_search
import sanitize_expression
import get_token

C_OPERANDS = ["+", "-", "*", "/", "&", "|", ">", "<", "=", "%", "^", "!", "~", "?", ":", "."]
C_UNARY_OPERANDS = ["!", "~", "&", "*", "-"]
C_KEYWORDS = ["if", "else", "for", "while", "return", "sizeof", "typeof"]
C_TYPE_MODIFIERS = ["const", "struct", "volatile", "enum", "register", "static", "union"]


def is_expression(var_ref, var_ref_arr):
    if "++" in var_ref or "--" in var_ref or get_token.get_eq_index(var_ref) is not None:
        return True
    if is_valid_varname(var_ref_arr[3]):
        if var_ref_arr[3] in C_KEYWORDS[:-2]:
            return True
        curr_char = 0
        while (curr_char < len(var_ref_arr[4]) and
               (var_ref_arr[4][curr_char] != "=" and var_ref_arr[4][curr_char] != ";" and var_ref_arr[4][curr_char] != "{")):
            if not is_valid_varname(var_ref_arr[4][curr_char]):
                return False
            curr_char += 1
        return True
    return is_func(var_ref) or is_control_flow_expr(var_ref)


def is_control_flow_expr(var_ref):
    for keyword in C_KEYWORDS[:-2]:
        keyword_match = has_token_match(var_ref, keyword)
        if keyword_match:
            return True
    return False


def is_func(var_ref):
    open_brackets_indices = [m.start() for m in re.finditer("\\[", var_ref)]
    bracket_indices = []
    for open_brackets_index in open_brackets_indices:
        bracket_end = recur_with_parenthesis(var_ref, open_brackets_index + 1, "[")
        if bracket_end >= len(var_ref):
            bracket_end = len(var_ref) - 1
        bracket_indices.append((open_brackets_index, bracket_end + 1))

    var_ref = sanitize_expression.remove_substring(var_ref, bracket_indices)

    args_start_indices = [m.start() for m in re.finditer("\\(", var_ref)]
    for args_start_index in args_start_indices:
        if args_start_index > 0 and is_valid_varname_char(var_ref[args_start_index-1]):
            func_name_start = args_start_index - 1
            while func_name_start > 0 and is_valid_varname_char(var_ref[func_name_start]):
                func_name_start -= 1
            if var_ref[func_name_start+1:args_start_index] not in C_KEYWORDS:
                return True
    return False


def has_mismatched_parenthesis(var_ref):
    mismatched_parenthesis, _ = check_mismatched_parenthesis(var_ref, 0, False)
    return mismatched_parenthesis


def check_mismatched_parenthesis(var_ref, curr_index, has_recurred):
    while curr_index < len(var_ref):
        if var_ref[curr_index] == "(":
            curr_index += 1
            while curr_index < len(var_ref) and var_ref[curr_index] != ")":
                if var_ref[curr_index] == "(":
                    mismatched_parenthesis, curr_index = check_mismatched_parenthesis(var_ref, curr_index, True)
                    if mismatched_parenthesis:
                        return True, curr_index
                curr_index += 1
            if curr_index == len(var_ref) or var_ref[curr_index] != ")":
                return True, curr_index
            elif has_recurred:
                return False, curr_index
            curr_index += 1
        elif var_ref[curr_index] == ")":
            return True, curr_index
        else:
            curr_index += 1
    return False, curr_index


def is_ref(var_ref, var_name, func_name, is_global):
    while var_name[0] == "*":
        var_name = var_name[1:]
    start_indices = [m.start() for m in re.finditer(var_name, var_ref)]
    check_passed = False
    for start_index in start_indices:
        if is_token_match(var_ref, start_index, len(var_name)):
            var_end_index = start_index + len(var_name)
            check_passed = check_passed or not is_type_name(var_ref, start_index, var_end_index, func_name, is_global)
    return check_passed


def is_type_name(var_ref, var_start_index, var_end_index, func_name, is_global):
    if var_end_index < len(var_ref):
        var_name = var_ref[var_start_index:var_end_index]
        if var_ref[var_end_index] == " ":
            next_token = var_ref[var_end_index+1:].strip()
            if is_valid_varname_char(next_token[0]) or next_token[0] == "*": #TODO: could be a multiplication
                return True
            elif is_global:
                return is_global_var_redeclaration(var_name, var_ref, var_start_index, next_token, func_name)
        elif is_global:
            return is_global_var_redeclaration(var_name, var_ref, var_start_index, var_ref[var_end_index:], func_name)
        else:
            return False
    return False


def is_global_var_redeclaration(var_name, var_ref, var_start_index, next_token, func_name):
    if next_token[0] == ";" or is_assignment_op(next_token, 0):
        if is_var_declaration(var_name, var_ref):
            if func_name not in var_search.out_of_scope:
                var_search.out_of_scope[func_name] = []
            var_search.out_of_scope[func_name].append(var_name)
            return True
        else:
            return False
    elif next_token[0] == "," or next_token[0] == ")":
        return is_func_arg_name(var_name, var_ref, var_start_index, func_name)


def is_func_arg_name(var_name, var_ref, var_start_index, func_name):
    for curr_index in range(var_start_index - 1, 0, -1):
        if var_ref[curr_index] == ',' or var_ref[curr_index] == "(" or var_ref[curr_index] == "." or var_ref[curr_index] == "=":
            return False
        elif is_valid_varname_char(var_ref[curr_index]):
            if func_name not in var_search.out_of_scope:
                var_search.out_of_scope[func_name] = []
            var_search.out_of_scope[func_name].append(var_name)
            return True
    return False


# def is_struct_field_name(var_ref, var_start_index, var_end_index):
#     return ((var_start_index > 0 and (var_ref[var_start_index-1] == ">" or var_ref[var_start_index-1] == ".")) or
#             (var_end_index < len(var_ref) and (var_ref[var_end_index] == "-" or var_ref[var_end_index] == ".")))


def is_var_declaration(var_name, var_ref):
    start_indices = [m.start() for m in re.finditer(var_name, var_ref)]
    for start_index in start_indices:
        end_index = start_index + len(var_name)
        curr_index = end_index
        while curr_index < len(var_ref) - 1 and var_ref[curr_index].isspace():
            curr_index += 1
        if (len(var_ref) > curr_index > 0 and (var_ref[curr_index] == ";" or var_ref[curr_index] == "(" or
                                               var_ref[curr_index] == ")" or var_ref[curr_index] == "," or
                                               var_ref[curr_index] == "[" or is_assignment_op(var_ref, curr_index))):
            if start_index > 0 and (var_ref[start_index-1].isspace() or var_ref[start_index-1] == "*"):
                curr_index = start_index - 1
                while curr_index > 0 and (var_ref[curr_index].isspace() or var_ref[curr_index] == "*"):
                    curr_index -= 1
                if is_valid_varname_char(var_ref[curr_index]):
                    token_end = curr_index
                    while curr_index >= 0 and not var_ref[curr_index].isspace() and not var_ref[curr_index] == "(":
                        curr_index -= 1
                    token = var_ref[curr_index+1:token_end+1]
                    while token[-1] == "*":
                        token = token[:-1]
                    if (token != "#define" and
                            (token == "" or token[-1] in C_OPERANDS or token.isnumeric() or token == "return" or
                             token == "else" or not is_valid_varname(token))):
                        return False
                    else:
                        return True
    return False


def recur_with_parenthesis(var_ref, curr_index, parenthesis_type):
    if parenthesis_type == "(":
        increment = 1
        open_parentheses = ["(", "["]
        close_parenthesis = ")"
    elif parenthesis_type == ")":
        increment = -1
        open_parentheses = [")", "]"]
        close_parenthesis = "("
    elif parenthesis_type == "[":
        increment = 1
        open_parentheses = ["(", "["]
        close_parenthesis = "]"
    else:
        increment = -1
        open_parentheses = [")", "]"]
        close_parenthesis = "["
    while curr_index < len(var_ref) and var_ref[curr_index] != close_parenthesis:
        if var_ref[curr_index] in open_parentheses:
            curr_index = recur_with_parenthesis(var_ref, curr_index + increment, var_ref[curr_index])
        curr_index += increment
    return curr_index


def has_var_name(var_ref, var_name):
    return has_token_match(var_ref, var_name)


def has_unary_operand(token):
    return token[0] in C_UNARY_OPERANDS or (len(token) > 1 and (token[:2]) == "++")


def is_valid_varname(token):
    for token_char in token:
        if not is_valid_varname_char(token_char) and token_char != "*":
            return False
    return True


def is_valid_varname_char(token):
    return token.isalnum() or token == "_"


def is_asm_block(var_ref):
    if "asm volatile (" in var_ref or "asm volatile(" in var_ref:
        return True
    asm_index = var_ref.find("asm (")
    if asm_index < 0:
        asm_index = var_ref.find("asm(")
        asm_len = len("asm(")
    else:
        asm_len = len("asm (")
    return asm_index >= 0 and is_token_match(var_ref, asm_index, asm_len)


def is_extern(var_ref):
    return has_token_match(var_ref, "extern")


def has_arg_names(func_args_declaration):
    for arg in func_args_declaration:
        if is_func_ptr(arg):
            continue

        tokens = arg.split()
        if tokens[0] in C_TYPE_MODIFIERS: #TODO: handle signed and unsigned
            if len(tokens) >= 3:
                arg_name = tokens[len(tokens) - 1]
            else:
                return False
        else:
            if len(tokens) >= 2:
                arg_name = tokens[len(tokens) - 1]
            else:
                return False

        while len(arg_name) > 0 and arg_name[0] == "*":
            arg_name = arg_name[1:]

        if arg_name == "" or arg_name.isnumeric():
            return False

    return True


def is_func_ptr(var_declaration):
    parenthesis_indices = [m.start() for m in re.finditer("\\(", var_declaration)]
    for parenthesis_index in parenthesis_indices:
        if var_declaration[parenthesis_index + 1] == "*":
            return True
    return False


def has_open_string(var_ref):
    return var_ref.count("\"") % 2 == 1


def is_assignment_op(token, curr_char):
    return (token[curr_char] == "=" and (curr_char == len(token) - 1 or token[curr_char + 1] != "=") and
            (curr_char == 0 or (token[curr_char - 1] != "=" and token[curr_char - 1] != "<" and token[curr_char - 1] != ">"
                                and token[curr_char - 1] != "!")))


def has_token_match(var_ref, token):
    start_indices = [m.start() for m in re.finditer(token, var_ref)]
    for start_index in start_indices:
        if is_token_match(var_ref, start_index, len(token)):
            return True
    return False


def is_token_match(var_ref, index, token_len):
    return ((index == 0 or not is_valid_varname_char(var_ref[index - 1])) and
            (index + token_len == len(var_ref) or not is_valid_varname_char(var_ref[index + token_len])))
