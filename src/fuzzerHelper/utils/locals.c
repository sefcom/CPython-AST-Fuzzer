#include "ast.h"

PyObject *get_locals_internal(int *index, asdl_stmt_seq *body_raw)
{
    for (int i = 0; i < body_raw->size; i++)
    {
        stmt_ty ele = body_raw->typed_elements[i];
        PyObject *re;
        switch (ele->kind)
        {
        case Assign_kind:
            if (ele->v.Assign.targets->size == 0 || ele->v.Assign.targets->typed_elements[0]->kind != Name_kind)
            {
                break;
            }
            if (*index == 0)
            {
                return ele->v.Assign.targets->typed_elements[0]->v.Name.id;
            }
            *index = *index - 1;
            break;
            RECURSIVE_CASE(FunctionDef, get_locals_internal, , )
            RECURSIVE_CASE(ClassDef, get_locals_internal, , )
            RECURSIVE_CASE(If, get_locals_internal, , )
            RECURSIVE_CASE(While, get_locals_internal, , )
            RECURSIVE_CASE(For, get_locals_internal, , )
            RECURSIVE_CASE(With, get_locals_internal, , )
        default:
            break;
        }
    }
    return NULL;
}

PyObject *get_locals(ast_data_t *data, int index)
{
    int idx = index;
    PyObject *re = get_locals_internal(&idx, data->mod->v.Module.body);
    if (re == NULL)
    {
        PANIC("no locals found: req %d, remaining %d\n", index, idx);
    }
    return re;
}