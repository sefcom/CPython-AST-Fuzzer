#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

const char *STMT_KIND_NAME[28] = {
    "FunctionDef",
    "AsyncFunctionDef",
    "ClassDef",
    "Return",
    "Delete",
    "Assign",
    "TypeAlias",
    "AugAssign",
    "AnnAssign",
    "For",
    "AsyncFor",
    "While",
    "If",
    "With",
    "AsyncWith",
    "Match",
    "Raise",
    "Try",
    "TryStar",
    "Assert",
    "Import",
    "ImportFrom",
    "Global",
    "Nonlocal",
    "Expr",
    "Pass",
    "Break",
    "Continue"
};

const char *MOD_KIND_NAME[4] = {
    "Module",
    "Interactive",
    "Expression",
    "FunctionType"
};


typedef struct{
    void *ast_buf;
    size_t ast_buf_size;
    size_t ast_buf_used;
    size_t ast_freelist_size;
} ast_data_t;


typedef enum{
    STRING,
    NUMBER
} python_obj_kind_t;

typedef struct{
    python_obj_kind_t kind;
    size_t offset;
    union{
        size_t number;
        const char *string;
    }val;
} python_obj_t;

void dump_stmt(stmt_ty stmt, int indent){
    for(int i = 0; i < indent; i ++){
        printf("\t");
    }
    printf("%s\n", STMT_KIND_NAME[stmt->kind]);
    
}

void dump_stmts(asdl_stmt_seq seq){
    for(int i = 0; i < seq.size; i ++){
        dump_stmt(seq.elements[i], 1);
        printf(",\n");
    }
}

void dump_mod(mod_ty root)
{
    printf("%s(body=[\n", MOD_KIND_NAME[root->kind]);
    switch (root->kind)
    {
    case Module_kind:
        dump_stmts(*(root->v.Module.body));
        break;
    case Interactive_kind:
        dump_stmts(*(root->v.Interactive.body));
        break;
    default:
        printf("Not implemented\n");
        break;
    }
    
    printf("])\n");
}

int main(int argc, char *argv[])
{
    printf("reading %s\n", argv[1]);
    FILE *fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc(len);
    fread(buf, 1, len, fp);
    fclose(fp);

    mod_ty root = (mod_ty)buf;
    dump_mod(root);

    return 0;
}