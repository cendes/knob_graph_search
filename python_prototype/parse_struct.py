import re
import check_expression
import sanitize_expression

NO_MATCH = -1


def get_root_name(var_name):
    dot_index = var_name.find(".")
    arrow_index = var_name.find("-")
    if dot_index > 0 or arrow_index > 0:
        var_name = var_name[:min(dot_index & 0xffffffffffffffff, arrow_index & 0xffffffffffffffff)]

    bracket_index = var_name.find("[")
    if bracket_index > 0:
        var_name = var_name[:bracket_index]

    while var_name[0] == "*" or var_name[0] == "&":
        var_name = var_name[1:]

    return var_name


def get_struct_hierarchy(var_name):
    root_name = get_root_name(var_name)
    hierarchy = []
    curr_index = len(root_name)
    while curr_index < len(var_name) and (var_name[curr_index] == "." or (
            var_name[curr_index] == "-" and curr_index < len(var_name) - 1 and var_name[curr_index + 1] == ">")):
        segment_name, curr_index = get_struct_segment(var_name, curr_index)
        hierarchy.append(segment_name)
    return root_name, hierarchy


def get_struct_segment(var_ref, curr_index):
    if var_ref[curr_index] == ".":
        curr_index += 1
    else:
        curr_index += 2
    segment_start = curr_index
    while (curr_index < len(var_ref) and
           (check_expression.is_valid_varname_char(var_ref[curr_index]) or var_ref[curr_index] == "*" or var_ref[curr_index] == "&" or
            var_ref[curr_index] == "(" or var_ref[curr_index] == ")" or var_ref[curr_index] == "[" or var_ref[curr_index] == "]")):
        if var_ref[curr_index] == "(" or var_ref[curr_index] == "[":
            curr_index = check_expression.recur_with_parenthesis(var_ref, curr_index + 1, var_ref[curr_index])
        curr_index += 1
    segment = var_ref[segment_start:curr_index]
    while segment[0] == "*":
        segment = segment[1:]
    if segment[0] == "(" and segment[len(segment) - 1] == ")":
        segment = segment[1:-1]
    while segment[0] == "*":
        segment = segment[1:]
    if "[" in segment:
        segment = segment[:segment.find("[")]
    if check_expression.is_func(segment):
        segment = segment[:segment.find("(")]
    return sanitize_expression.remove_casts(segment.strip()), curr_index


def get_struct_matches(var_ref, root_name, field_hierarchy):
    start_indices = [m.start() for m in re.finditer(root_name, var_ref)]
    hierarchy_indices = []
    for start_index in start_indices:
        if start_index == 0 or not check_expression.is_valid_varname_char(var_ref[start_index - 1]):
            curr_index = start_index + len(root_name)
            hierarchy_index = 0
            while (curr_index < len(var_ref)
                   and (var_ref[curr_index] == "."
                        or (var_ref[curr_index] == "-" and curr_index < len(var_ref) - 1 and var_ref[curr_index + 1] == ">"))):
                segment_name, curr_index = get_struct_segment(var_ref, curr_index)
                if " " in segment_name:
                    match_found = is_struct_segment_in_expr(field_hierarchy, hierarchy_index, segment_name)
                    if not match_found:
                        hierarchy_index = NO_MATCH
                        break

                if hierarchy_index == len(field_hierarchy) or segment_name != field_hierarchy[hierarchy_index]:
                    hierarchy_index = NO_MATCH
                    break
                hierarchy_index += 1

            if hierarchy_index >= 0:
                hierarchy_indices.append(hierarchy_index)

    return hierarchy_indices


def is_struct_segment_in_expr(field_hierarchy, hierarchy_index, segment_name):
    match_indices = [m.start() for m in re.finditer(field_hierarchy[hierarchy_index], segment_name)]
    match_found = False
    for match_index in match_indices:
        if ((match_index == 0 or not check_expression.is_valid_varname_char(segment_name[match_index - 1])) and
                (match_index == len(segment_name) - 1 or not check_expression.is_valid_varname_char(
                    segment_name[match_index + 1]))):
            match_found = True
            break

    if match_found:
        return True
    else:
        return False
