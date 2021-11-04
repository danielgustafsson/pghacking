/*-------------------------------------------------------------------------
 *
 * llvmjit_wrap.cpp
 *	  Parts of the LLVM interface not (yet) exposed to C.
 *
 * Copyright (c) 2016-2023, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/lib/llvm/llvmjit_wrap.cpp
 *
 *-------------------------------------------------------------------------
 */

extern "C"
{
#include "postgres.h"
}

#include <llvm-c/Core.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>
#include <llvm-c/Transforms/PassManagerBuilder.h>

/* Avoid macro clash with LLVM's C++ headers */
#undef Min

#include <llvm/ADT/Statistic.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/PassTimingInfo.h>
#include <llvm/MC/SubtargetFeature.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/Timer.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "jit/llvmjit.h"


/*
 * C-API extensions.
 */
#if defined(HAVE_DECL_LLVMGETHOSTCPUNAME) && !HAVE_DECL_LLVMGETHOSTCPUNAME
char *LLVMGetHostCPUName(void) {
	return strdup(llvm::sys::getHostCPUName().data());
}
#endif


#if defined(HAVE_DECL_LLVMGETHOSTCPUFEATURES) && !HAVE_DECL_LLVMGETHOSTCPUFEATURES
char *LLVMGetHostCPUFeatures(void) {
	llvm::SubtargetFeatures Features;
	llvm::StringMap<bool> HostFeatures;

	if (llvm::sys::getHostCPUFeatures(HostFeatures))
		for (auto &F : HostFeatures)
			Features.AddFeature(F.first(), F.second);

	return strdup(Features.getString().c_str());
}
#endif

/*
 * Like LLVM's LLVMGetAttributeCountAtIndex(), works around a bug in LLVM 3.9.
 *
 * In LLVM <= 3.9, LLVMGetAttributeCountAtIndex() segfaults if there are no
 * attributes at an index (fixed in LLVM commit ce9bb1097dc2).
 */
unsigned
LLVMGetAttributeCountAtIndexPG(LLVMValueRef F, uint32 Idx)
{
	/*
	 * This is more expensive, so only do when using a problematic LLVM
	 * version.
	 */
#if LLVM_VERSION_MAJOR < 4
	if (!llvm::unwrap<llvm::Function>(F)->getAttributes().hasAttributes(Idx))
		return 0;
#endif

	/*
	 * There is no nice public API to determine the count nicely, so just
	 * always fall back to LLVM's C API.
	 */
	return LLVMGetAttributeCountAtIndex(F, Idx);
}

static inline llvm::PassManagerBuilder *
unwrap(LLVMPassManagerBuilderRef P) {
    return reinterpret_cast<llvm::PassManagerBuilder*>(P);
}

static inline LLVMPassManagerBuilderRef
wrap(llvm::PassManagerBuilder *P) {
	return reinterpret_cast<LLVMPassManagerBuilderRef>(P);
}

static inline llvm::TargetLibraryInfoImpl *
unwrap(LLVMTargetLibraryInfoRef P) {
	return reinterpret_cast<llvm::TargetLibraryInfoImpl*>(P);
}

static inline LLVMTargetLibraryInfoRef
wrap(const llvm::TargetLibraryInfoImpl *P) {
	llvm::TargetLibraryInfoImpl *X = const_cast<llvm::TargetLibraryInfoImpl*>(P);
	return reinterpret_cast<LLVMTargetLibraryInfoRef>(X);
}

static llvm::TargetMachine *unwrap(LLVMTargetMachineRef P) {
	return reinterpret_cast<llvm::TargetMachine *>(P);
}

static inline LLVMTargetMachineRef
wrap(const llvm::TargetMachine *P) {
	return reinterpret_cast<LLVMTargetMachineRef>(const_cast<llvm::TargetMachine *>(P));
}

LLVMTargetLibraryInfoRef
LLVMGetTargetLibraryInfo(LLVMTargetMachineRef T)
{
	llvm::TargetLibraryInfoImpl *TLI =
		new llvm::TargetLibraryInfoImpl(unwrap(T)->getTargetTriple());

	return wrap(TLI);
}

void
LLVMPassManagerBuilderUseLibraryInfo(LLVMPassManagerBuilderRef PMBR,
									 LLVMTargetLibraryInfoRef TLI) {
	unwrap(PMBR)->LibraryInfo = unwrap(TLI);
}

void
LLVMPassManagerBuilderSetMergeFunctions(
	struct LLVMOpaquePassManagerBuilder *PMBR,
	bool value)
{
#if LLVM_VERSION_MAJOR >= 7
	unwrap(PMBR)->MergeFunctions = true;;
#endif
}

void
LLVMEnableStatistics()
{
	llvm::EnableStatistics(false /* print at shutdown */);
}

void
LLVMPrintAllTimers(bool clear)
{
	std::string s;
	llvm::raw_string_ostream o(s);

	if (llvm::TimePassesIsEnabled)
	{
		llvm::TimerGroup::printAll(o);
		if (clear)
			llvm::TimerGroup::clearAll();
	}

	if (llvm::AreStatisticsEnabled())
	{
		llvm::PrintStatistics(o);
		if (clear)
			llvm::ResetStatistics();
	}

	if (s.size() > 0)
		ereport(LOG, (errmsg("statistics: %s", s.c_str())));
}
