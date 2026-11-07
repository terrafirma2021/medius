/* Medius v3.4.7 device — C views of GCC C++ RTTI/cast helpers and destructors. */
#include "../include/types.h"

/* Native entry: 0x42017f24. */
/* Original function-byte SHA-256:
 * 56315cf4b8948a569f6803be3d3792944bb518b5fd3089c85ffd582f340ddca0. */
/* __si_class_type_info non-deleting destructor: write its vtable address
 * point, then invoke class_type_info destruction on the same address. The
 * base destructor replaces that vptr again; no name/base allocation is freed.
 */
void cxx_si_type_info_destroy(MediusCxxSingleBaseTypeInfo *self)
{
    self->type.vtable = MEDIUS_CXX_SI_VTABLE;
    cxx_class_type_info_destroy(&self->type);
}

/* Native entry: 0x42017f38. */
/* Original function-byte SHA-256:
 * 3b9b8f8cace2891f03b1cb1e0eef09b26073fc06fe039708c1c9861d016840c9. */
/* __si_class_type_info deleting destructor: destroy, then sized-delete
 * the SAME pointer with native size12. Lower delete ignores size and frees it.
 * No NULL check or separate release of name/base RTTI records.
 */
void cxx_si_type_info_delete(MediusCxxSingleBaseTypeInfo *self)
{
    cxx_si_type_info_destroy(self);
    cxx_operator_delete_sized(self,12U);
}

/* Native entry: 0x42017f50. */
/* Original function-byte SHA-256:
 * ae4881c78efab57d94bc182f8c70455fd6a71d156fda6eb51923e3e3bd26bab8. */
/* Compiler-specialized std::type_info equality for SI RTTI: arguments are
 * already-extracted name pointers, not type_info objects. Pointer identity is
 * equal, including NULL==NULL. Otherwise left leading '*' forbids matching;
 * only a leading '*' on RIGHT is skipped before strcmp. This is asymmetric
 * non-unique-name handling, not wildcard matching. Other NULLs are unchecked.
 */
bool cxx_si_type_name_equal(const char *left,const char *right)
{
    if (left == right)
        return true;
    if (*left == '*')
        return false;
    if (*right == '*')
        ++right;
    return strcmp(left,right) == 0;
}

/* Native entry: 0x42017f80. */
/* Original function-byte SHA-256:
 * 14c2eb7c49331ab5322e50b166cfa15f9f11c95dc66112125507f3fa7bffafd7. */
/* __si_class_type_info dynamic-cast search, with8 windowed-ABI arguments.
 * Cache own name; compare target first. On a target match store destination
 * pointer then access path. A nonnegative source offset sets dst2src to6
 * (contained public) only when object+offset==source_object, otherwise1.
 * Negative offset-2 sets1; other negatives leave the previous field intact.
 * Address addition preserves native32-bit wrap.
 *
 * If target does not match, equal object/source pointers plus matching source
 * name stores only whole2src=access_path. Otherwise freshly load base RTTI and
 * its vtable+0x1c, forwarding ALL arguments unchanged. Return that virtual
 * ambiguity result; local matches return false. No NULL/vtable/cycle guard,
 * object adjustment for this single nonvirtual base, or result initialization.
 */
bool cxx_si_type_info_do_dyncast(const MediusCxxSingleBaseTypeInfo *self,int source_to_destination,
    unsigned int access_path,const CxxTypeInfo *target,const void *object,
    const CxxTypeInfo *source,const void *source_object,MediusCxxDynamicCastResultView *result)
{
    const char *name = self->type.name;
    if (cxx_si_type_name_equal(name,target->name)) {
        result->destination_pointer = object;
        result->whole_to_destination = access_path;
        if (source_to_destination >= 0) {
            result->destination_to_source =
                (unsigned int)source_object == (unsigned int)object + (unsigned int)source_to_destination ? 6U : 1U;
        } else if (source_to_destination == -2) {
            result->destination_to_source = 1U;
        }
        return false;
    }
    if (object == source_object && cxx_si_type_name_equal(name,source->name)) {
        result->whole_to_source = access_path;
        return false;
    }
    const CxxTypeInfo *base = self->base_type;
    return base->vtable->dynamic_cast_search(base,source_to_destination,access_path,
        target,object,source,source_object,result);
}

/* Native entry: 0x42017ff8. */
/* Original function-byte SHA-256:
 * 4e3bdc74bb7539e5a4875918b5920b1f9647a377ad6334e096539a63598d1fde. */
/* __si_class_type_info public-source search: identical object/source
 * addresses and matching own/source name return6 (contained public). Otherwise
 * freshly load base RTTI/vtable+0x20 and delegate with the offset and pointers
 * unchanged. No single-base pointer adjustment, NULL check or cycle limit.
 */
unsigned int cxx_si_type_info_find_public_source(const MediusCxxSingleBaseTypeInfo *self,
    int source_to_destination,const void *object,const CxxTypeInfo *source,const void *source_object)
{
    if (source_object == object && cxx_si_type_name_equal(self->type.name,source->name))
        return 6U;
    const CxxTypeInfo *base = self->base_type;
    return base->vtable->find_public_source(base,source_to_destination,object,source,source_object);
}

/* Native entry: 0x42018024. */
/* Original function-byte SHA-256:
 * 63cc37b8e83d3ce19c686fa062299913db789b7924cbb71322b198e96ff3d33e. */
/* __si_class_type_info upcast helper: try the class implementation on this
 * type first. On false, freshly load base RTTI/vtable+0x18 and delegate without
 * adjusting object/result. Return the direct or virtual bool unchanged.
 */
bool cxx_si_type_info_do_upcast(const MediusCxxSingleBaseTypeInfo *self,
    const CxxTypeInfo *target,const void *object,MediusCxxUpcastResult *result)
{
    bool matched = cxx_class_type_info_do_upcast(&self->type,target,object,result);
    if (matched)
        return matched;
    const CxxTypeInfo *base = self->base_type;
    return base->vtable->upcast_result(base,target,object,result);
}

/* Native entry: 0x42018050. */
/* Original function-byte SHA-256:
 * c53c970b2c4416d8bb3788b14cba105393eb60b1a34addd60217cb9638595ee0. */
/* std::bad_alloc::what(): return the immutable native DROM string
 * "std::bad_alloc". Ignores this; no allocation, formatting or state access.
 */
const char *cxx_bad_alloc_what(const void *ignored_self)
{
    return (const char *)0x3c047488U;
}

/* Native entry: 0x42018058. */
/* Original function-byte SHA-256:
 * 67dfdb01be244c596f86ac53b5798c55c7ec75edc2acf1bc6179b97cb4e57ec3. */
/* std::bad_alloc non-deleting destructor: write its vptr then call the
 * empty std::exception destructor. Leaves this vptr in place; frees nothing.
 */
void cxx_bad_alloc_destroy(MediusCxxExceptionObject *self)
{
    self->vtable = MEDIUS_CXX_BAD_ALLOC_VTABLE;
    cxx_exception_destroy(self);
}

/* Native entry: 0x4201806c. */
/* Original function-byte SHA-256:
 * a87770762ae3dbf4fae77f0fcfaef61a2243be51e223aa3d0812dbbafb2babc7. */
/* std::bad_alloc deleting destructor: destroy, then sized-delete the same
 * pointer with4. Lower delete ignores that size; no NULL check is supplied.
 */
void cxx_bad_alloc_delete(MediusCxxExceptionObject *self)
{
    cxx_bad_alloc_destroy(self);
    cxx_operator_delete_sized(self,4U);
}

/* Native entry: 0x42018084. */
/* Original function-byte SHA-256:
 * 5bc69dbf611429c1b24e8ca56a8561c80b1efc4b8adfbd86cec6500e6eb315b6. */
/* __class_type_info non-deleting destructor: set the class vptr, then call
 * the empty type_info destructor. Name storage is borrowed and not freed.
 */
void cxx_class_type_info_destroy(CxxTypeInfo *self)
{
    self->vtable = MEDIUS_CXX_CLASS_VTABLE;
    cxx_type_info_destroy(self);
}

/* Native entry: 0x42018098. */
/* Original function-byte SHA-256:
 * ed920c05d1c5df2a38483dd3eecc817664b1185d1b2bbc07582c741f0a2b3f03. */
/* __class_type_info deleting destructor: destroy, then sized-delete the
 * SAME pointer with8; lower delete ignores size. No name allocation release.
 */
void cxx_class_type_info_delete(CxxTypeInfo *self)
{
    cxx_class_type_info_destroy(self);
    cxx_operator_delete_sized(self,8U);
}

/* Native entry: 0x420180b0. */
/* Original function-byte SHA-256:
 * d01a41085a28e9ab6855d6a182017aec5323b13f13ae411d98a7e3d20f45faf8. */
/* Separate compiler-specialized std::type_info name comparison for class
 * RTTI. Preserve its native identity even though behavior equals the SI copy:
 * same pointer true; differing left '*' false; skip right '*' only; strcmp.
 * No wildcard matching, case folding or NULL guard after unequal pointers.
 */
bool cxx_class_type_name_equal(const char *left,const char *right)
{
    if (left == right)
        return true;
    if (*left == '*')
        return false;
    if (*right == '*')
        ++right;
    return strcmp(left,right) == 0;
}

/* Native entry: 0x420180e0. */
/* Original function-byte SHA-256:
 * 2e958de900a3080ecdaabd46bfef6f56ea05b65e6e62e66270b367dac0f2ac0e. */
/* __class_type_info result-producing upcast: compare own and target names.
 * On match write nonvirtual base sentinel pointer0x8 FIRST, then destination
 * object, then part2dst=6 (contained public). source_details stays unchanged.
 * Sentinel0x8 is pointer arithmetic NULL+sizeof(__class_type_info), never a
 * dereferenceable object. On false leave the entire result unchanged.
 */
bool cxx_class_type_info_do_upcast(const CxxTypeInfo *self,
    const CxxTypeInfo *target,const void *object,MediusCxxUpcastResult *result)
{
    bool matched = cxx_class_type_name_equal(self->name,target->name);
    if (matched) {
        result->base_type = (const CxxTypeInfo *)8U;
        result->destination_pointer = object;
        result->part_to_destination = 6U;
    }
    return matched;
}

/* Native entry: 0x42018100. */
/* Original function-byte SHA-256:
 * d72901118f17d332394a5e30dce20fee3783d73793132229799f3de45da4953b. */
/* __class_type_info dynamic-cast search for a class with no base traversal.
 * Cache own name. Equal object/source addresses and matching source name
 * update only whole2src. Otherwise a target-name match writes destination
 * object, whole2dst=access_path, dst2src=1 (not contained), in that order.
 * Offset is ignored. Other fields remain unchanged. Always return false,
 * meaning no ambiguous match was found, not a success/failure code.
 */
bool cxx_class_type_info_do_dyncast(const CxxTypeInfo *self,int ignored_source_to_destination,
    unsigned int access_path,const CxxTypeInfo *target,const void *object,
    const CxxTypeInfo *source,const void *source_object,MediusCxxDynamicCastResultView *result)
{
    const char *name = self->name;
    if (object == source_object && cxx_class_type_name_equal(name,source->name)) {
        result->whole_to_source = access_path;
    } else if (cxx_class_type_name_equal(name,target->name)) {
        result->destination_pointer = object;
        result->whole_to_destination = access_path;
        result->destination_to_source = 1U;
    }
    return false;
}

/* Native entry: 0x42018138. */
/* Original function-byte SHA-256:
 * 454b308f82b36053c95476cdd96c737a4ebbd418f6f2203a44bfc810df4aae36. */
/* __class_type_info catch matching: equal own/thrown names return true.
 * On mismatch and unsigned outer<4, call THROWN type's vtable+0x14 upcast
 * with this caught type and the object-pointer slot. That callback may adjust
 * *object. Otherwise false. No object read/adjustment on the direct match,
 * and no NULL/type/vtable validation or local exception throw.
 */
bool cxx_class_type_info_do_catch(const CxxTypeInfo *self,
    const CxxTypeInfo *thrown,void **object,unsigned int outer)
{
    bool matched = cxx_class_type_name_equal(self->name,thrown->name);
    if (!matched && outer < 4U)
        return thrown->vtable->upcast_object(thrown,self,object);
    return matched;
}

/* Native entry: 0x4202144c. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* std::type_info non-deleting destructor: native ENTRY/RETW only.
 * Ignores this, does not reset the vptr, free the name or touch storage.
 */
void cxx_type_info_destroy(CxxTypeInfo *ignored_self)
{
}

/* Native entry: 0x42021498. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* std::exception non-deleting destructor: native ENTRY/RETW only.
 * Ignores this; no vptr update, allocation release or observable state access.
 */
void cxx_exception_destroy(MediusCxxExceptionObject *ignored_self)
{
}

/* Native entry: 0x42021454. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Shared std::type_info __is_pointer_p/__is_function_p entry. Return false
 * without reading this or memory. Both class vtable slots share this address;
 * they remain one native function identity, not two reconstructed functions.
 */
bool cxx_type_info_is_pointer_or_function(const CxxTypeInfo *ignored_self)
{
    return false;
}

/* Native entry: 0x4202145c. */
/* Original function-byte SHA-256:
 * c14ae46e7db01f76af4f15b708b3339d3873c9e816d5e71f4c890552f446d31b. */
/* __class_type_info object-slot upcast: initialize a16-byte stack result,
 * setting destination0, part2dst0, base_type0, then load own vtable+0x18 and
 * the caller's object pointer before setting source_details16 (unknown flags).
 * Call the virtual result-producing upcast; its returned bool is ignored.
 * Accept only when BOTH bits in result.part2dst mask6 are set; additional
 * bits are allowed. On acceptance copy result.destination_pointer back to
 * the caller slot and return true. Otherwise leave the slot unchanged and
 * return false. No NULL, vtable, object-storage or result-pointer validation.
 */
bool cxx_class_type_info_upcast_object(const CxxTypeInfo *self,const CxxTypeInfo *target,void **object)
{
    MediusCxxUpcastResult result;
    result.destination_pointer = 0;
    result.part_to_destination = 0;
    result.base_type = 0;
    const volatile MediusCxxClassVtable *vtable = self->vtable;
    bool (*upcast)(const CxxTypeInfo *,const CxxTypeInfo *,const void *,MediusCxxUpcastResult *) = vtable->upcast_result;
    void *value = *(void *volatile *)object;
    result.source_details = 16;
    (void)upcast(self,target,value,&result);
    bool accepted = (result.part_to_destination & 6U) == 6U;
    if (accepted)
        *(void *volatile *)object = (void *)result.destination_pointer;
    return accepted;
}

/* Native entry: 0x4202148c. */
/* Original function-byte SHA-256:
 * 2b16cbcb6cbad44a1218a05f108a24febce5f235bc4b7b74fe6cd96a9227e2e6. */
/* __class_type_info public-source helper for the base-less class case:
 * return6 (contained public) iff object and source_object addresses agree,
 * otherwise1 (not contained). This, type and offset arguments are ignored;
 * no pointer dereference, type-name comparison or source search occurs here.
 */
unsigned int cxx_class_type_info_find_public_source(const CxxTypeInfo *ignored_self,
    int ignored_source_to_destination,const void *object,const CxxTypeInfo *ignored_source,const void *source_object)
{
    return object == source_object ? 6U : 1U;
}
